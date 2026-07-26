<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Http\ClientCredentials;
use Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns\AuthenticatesConfidentialClient;
use Bambamboole\LaravelOidc\Server\Token\TokenInspector;
use Carbon\CarbonInterface;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Laravel\Passport\RefreshToken;
use Laravel\Passport\Token;
use Lcobucci\JWT\Token\Plain;

class IntrospectionController
{
    use AuthenticatesConfidentialClient;

    public function __invoke(Request $request, ClientCredentials $credentials, TokenInspector $inspector): JsonResponse
    {
        [$clientId, $tokenValue] = $this->authenticateConfidentialClient($request, $credentials);

        if ($this->isRefreshTokenHint($request)) {
            return $this->introspectRefreshToken($tokenValue, $clientId, $inspector);
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

    private function introspectRefreshToken(string $tokenValue, string $clientId, TokenInspector $inspector): JsonResponse
    {
        $payload = $inspector->refreshTokenPayload($tokenValue);

        if ($payload === null || (string) ($payload->client_id ?? '') !== $clientId) {
            return response()->json(['active' => false]);
        }

        $refreshTokenId = $payload->refresh_token_id ?? null;
        $refreshToken = is_string($refreshTokenId) ? Passport::refreshToken()->newQuery()->find($refreshTokenId) : null;
        $expireTime = $payload->expire_time ?? null;

        if (! $refreshToken instanceof RefreshToken
            || (bool) $refreshToken->getAttribute('revoked')
            || ! is_int($expireTime)
            || $expireTime < time()) {
            return response()->json(['active' => false]);
        }

        return response()->json(array_filter([
            'active' => true,
            'client_id' => $clientId,
            'sub' => $this->subject($payload->user_id ?? null),
            'exp' => $expireTime,
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
