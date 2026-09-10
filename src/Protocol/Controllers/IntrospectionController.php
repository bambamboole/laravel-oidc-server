<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Controllers;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Clients\ClientAuthenticator;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\PresentedToken;
use Bambamboole\LaravelOidc\Server\Tokens\PresentedTokenResolver;
use Carbon\CarbonInterface;
use DateTimeInterface;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lcobucci\JWT\Token\Plain;

/**
 * RFC 7662. Besides the client a token was issued to, any client named in an
 * access token's audience may introspect it — that is how a resource server
 * validates an exchanged token whose client_id is the requesting client.
 * Anything else — unknown, expired, revoked, or another client's token — is
 * `active: false` (§2.2), never an error.
 */
class IntrospectionController
{
    public function __construct(
        private readonly PresentedTokenResolver $tokens,
        private readonly IssuerResolver $issuer,
    ) {}

    public function __invoke(Request $request, ClientAuthenticator $clients): JsonResponse
    {
        $client = $clients->authenticate($request);

        if (! $client->confidential()) {
            throw OAuthServerException::invalidClient('Only confidential clients may introspect tokens.');
        }

        $presented = $this->tokens->fromRequest($request);

        if ($presented === null) {
            return $this->inactive();
        }

        return $presented->isRefreshToken()
            ? $this->introspectRefreshToken($presented, $client)
            : $this->introspectAccessToken($presented, $client);
    }

    /** RFC 7662 §2.2, with the JWT claims RFC 9068 §2.2 puts in the token. */
    private function introspectAccessToken(PresentedToken $presented, Client $client): JsonResponse
    {
        $token = $presented->accessToken;
        $jwt = $presented->jwt;
        $expiresAt = $token->expires_at;

        if ($jwt === null
            || $token->revoked
            || ($expiresAt instanceof CarbonInterface && $expiresAt->isPast())
            || (! $token->issuedTo($client) && ! $this->callerInAudience($client, $jwt))) {
            return $this->inactive();
        }

        $claims = $jwt->claims();

        return $this->active([
            'token_type' => 'Bearer',
            'scope' => implode(' ', $token->scopes ?? []),
            'client_id' => $token->client?->client_id,
            'sub' => $this->subject($token->user_id),
            'exp' => $expiresAt?->getTimestamp(),
            'iat' => $this->timestamp($claims->get('iat')),
            'nbf' => $this->timestamp($claims->get('nbf')),
            'jti' => $token->id,
            'iss' => $this->issuer->url(),
            'aud' => $this->audience($jwt),
        ]);
    }

    private function introspectRefreshToken(PresentedToken $presented, Client $client): JsonResponse
    {
        $refreshToken = $presented->refreshToken;
        $accessToken = $presented->accessToken;

        if (! $refreshToken instanceof RefreshToken
            || ! $accessToken->issuedTo($client)
            || $refreshToken->revoked
            || ! $refreshToken->expires_at instanceof CarbonInterface
            || $refreshToken->expires_at->isPast()) {
            return $this->inactive();
        }

        return $this->active([
            'scope' => implode(' ', $accessToken->scopes ?? []),
            'client_id' => $accessToken->client?->client_id,
            'sub' => $this->subject($accessToken->user_id),
            'exp' => $refreshToken->expires_at->getTimestamp(),
            'iss' => $this->issuer->url(),
        ]);
    }

    /** @param  array<string, mixed>  $members */
    private function active(array $members): JsonResponse
    {
        return response()->json(['active' => true, ...array_filter($members, fn (mixed $value): bool => $value !== null)]);
    }

    private function inactive(): JsonResponse
    {
        return response()->json(['active' => false]);
    }

    private function callerInAudience(Client $client, Plain $jwt): bool
    {
        return in_array($client->client_id, $this->audience($jwt), true);
    }

    /** @return list<string> */
    private function audience(Plain $jwt): array
    {
        $aud = $jwt->claims()->get('aud');

        return array_values(array_map(strval(...), array_filter(is_array($aud) ? $aud : [$aud], is_scalar(...))));
    }

    private function timestamp(mixed $claim): ?int
    {
        if ($claim instanceof DateTimeInterface) {
            return $claim->getTimestamp();
        }

        return is_numeric($claim) ? (int) $claim : null;
    }

    private function subject(mixed $userId): ?string
    {
        if ($userId === null || $userId === '') {
            return null;
        }

        return (string) $userId;
    }
}
