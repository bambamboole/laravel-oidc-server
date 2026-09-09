<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Controllers;

use Bambamboole\LaravelOidc\Server\Clients\ClientCredentials;
use Bambamboole\LaravelOidc\Server\Clients\Concerns\AuthenticatesConfidentialClient;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Bambamboole\LaravelOidc\Server\Tokens\TokenInspector;
use Carbon\CarbonInterface;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lcobucci\JWT\Token\Plain;

class IntrospectionController
{
    use AuthenticatesConfidentialClient;

    public function __invoke(Request $request, ClientCredentials $credentials, TokenInspector $inspector): JsonResponse
    {
        [$clientId, $tokenValue] = $this->authenticateConfidentialClient($request, $credentials);

        if ($this->isRefreshTokenHint($request)) {
            return $this->introspectRefreshToken($tokenValue, $clientId);
        }

        $parsed = $inspector->parse($tokenValue);
        $token = $parsed !== null ? $inspector->tokenForParsed($parsed) : null;

        if ($parsed === null || ! $token instanceof Token) {
            return response()->json(['active' => false]);
        }

        $expiresAt = $token->getAttribute('expires_at');
        $tokenClientId = (string) $token->getAttribute('client_id');

        if ((bool) $token->getAttribute('revoked')
            || ($expiresAt instanceof CarbonInterface && $expiresAt->isPast())
            || ($tokenClientId !== $clientId && ! $this->callerInAudience($clientId, $parsed))) {
            return response()->json(['active' => false]);
        }

        $scopes = $token->getAttribute('scopes');

        return response()->json(array_filter([
            'active' => true,
            'token_type' => 'Bearer',
            'scope' => implode(' ', is_array($scopes) ? $scopes : []),
            'client_id' => $tokenClientId,
            'sub' => $this->subject($token->getAttribute('user_id')),
            'exp' => $expiresAt instanceof CarbonInterface ? $expiresAt->getTimestamp() : null,
        ], fn (mixed $value): bool => $value !== null));
    }

    private function introspectRefreshToken(string $tokenValue, string $clientId): JsonResponse
    {
        // A refresh token carries no realm of its own; it inherits the one of
        // the access token it was issued alongside.
        $refreshToken = RefreshToken::query()
            ->with('accessToken')
            ->whereIn('access_token_id', Token::query()->inRealm()->select('id'))
            ->find($tokenValue);
        $accessToken = $refreshToken?->accessToken;

        if (! $refreshToken instanceof RefreshToken
            || ! $accessToken instanceof Token
            || (string) $accessToken->getAttribute('client_id') !== $clientId
            || (bool) $refreshToken->getAttribute('revoked')
            || ! $refreshToken->expires_at instanceof CarbonInterface
            || $refreshToken->expires_at->isPast()) {
            return response()->json(['active' => false]);
        }

        $scopes = $accessToken->getAttribute('scopes');

        return response()->json(array_filter([
            'active' => true,
            'scope' => implode(' ', is_array($scopes) ? $scopes : []),
            'client_id' => $clientId,
            'sub' => $this->subject($accessToken->getAttribute('user_id')),
            'exp' => $refreshToken->expires_at->getTimestamp(),
        ], fn (mixed $value): bool => $value !== null));
    }

    /**
     * RFC 7662 leaves the caller-authorization policy open. Besides the client
     * a token was issued to, any client named in its audience may introspect
     * it — that is how a resource server validates an exchanged token whose
     * client_id is the requesting client.
     */
    private function callerInAudience(string $clientId, Plain $parsed): bool
    {
        $aud = $parsed->claims()->get('aud');
        $aud = is_array($aud) ? $aud : [$aud];

        return in_array($clientId, array_map(strval(...), array_filter($aud, is_scalar(...))), true);
    }

    private function subject(mixed $userId): ?string
    {
        if ($userId === null || $userId === '') {
            return null;
        }

        return (string) $userId;
    }
}
