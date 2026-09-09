<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Controllers;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Clients\ClientAuthenticator;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Bambamboole\LaravelOidc\Server\Tokens\TokenInspector;
use Carbon\CarbonInterface;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lcobucci\JWT\Token\Plain;

/**
 * RFC 7662. Besides the client a token was issued to, any client named in an
 * access token's audience may introspect it — that is how a resource server
 * validates an exchanged token whose client_id is the requesting client.
 */
class IntrospectionController
{
    public function __invoke(Request $request, ClientAuthenticator $clients, TokenInspector $inspector): JsonResponse
    {
        $client = $clients->authenticate($request);

        if (! $client->confidential()) {
            throw OAuthServerException::invalidClient('Only confidential clients may introspect tokens.');
        }

        $tokenValue = (string) $request->input('token');

        if ($request->input('token_type_hint') === 'refresh_token') {
            return $this->introspectRefreshToken($tokenValue, $client);
        }

        $parsed = $inspector->parse($tokenValue);
        $token = $parsed !== null ? $inspector->tokenForParsed($parsed) : null;

        if ($parsed === null || ! $token instanceof Token) {
            return response()->json(['active' => false]);
        }

        $expiresAt = $token->expires_at;

        if ($token->revoked
            || ($expiresAt instanceof CarbonInterface && $expiresAt->isPast())
            || (! $token->issuedTo($client) && ! $this->callerInAudience($client, $parsed))) {
            return response()->json(['active' => false]);
        }

        return response()->json(array_filter([
            'active' => true,
            'token_type' => 'Bearer',
            'scope' => implode(' ', $token->scopes ?? []),
            'client_id' => $token->client?->client_id,
            'sub' => $this->subject($token->user_id),
            'exp' => $expiresAt?->getTimestamp(),
        ], fn (mixed $value): bool => $value !== null));
    }

    private function introspectRefreshToken(string $tokenValue, Client $client): JsonResponse
    {
        // A refresh token carries no realm of its own; it inherits the one of
        // the access token it was issued alongside.
        $refreshToken = RefreshToken::query()
            ->with('accessToken.client')
            ->whereIn('access_token_id', Token::query()->inRealm()->select('id'))
            ->find($tokenValue);
        $accessToken = $refreshToken?->accessToken;

        if (! $refreshToken instanceof RefreshToken
            || ! $accessToken instanceof Token
            || ! $accessToken->issuedTo($client)
            || $refreshToken->revoked
            || ! $refreshToken->expires_at instanceof CarbonInterface
            || $refreshToken->expires_at->isPast()) {
            return response()->json(['active' => false]);
        }

        return response()->json(array_filter([
            'active' => true,
            'scope' => implode(' ', $accessToken->scopes ?? []),
            'client_id' => $client->client_id,
            'sub' => $this->subject($accessToken->user_id),
            'exp' => $refreshToken->expires_at->getTimestamp(),
        ], fn (mixed $value): bool => $value !== null));
    }

    private function callerInAudience(Client $client, Plain $parsed): bool
    {
        $aud = $parsed->claims()->get('aud');
        $aud = is_array($aud) ? $aud : [$aud];

        return in_array($client->client_id, array_map(strval(...), array_filter($aud, is_scalar(...))), true);
    }

    private function subject(mixed $userId): ?string
    {
        if ($userId === null || $userId === '') {
            return null;
        }

        return (string) $userId;
    }
}
