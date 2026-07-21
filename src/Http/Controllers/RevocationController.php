<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http\Controllers;

use Bambamboole\LaravelOidc\Http\ClientCredentials;
use Bambamboole\LaravelOidc\Http\Controllers\Concerns\AuthenticatesConfidentialClient;
use Bambamboole\LaravelOidc\Token\TokenInspector;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;

class RevocationController
{
    use AuthenticatesConfidentialClient;

    public function __invoke(Request $request, ClientCredentials $credentials, TokenInspector $inspector): Response
    {
        [$clientId, $tokenValue] = $this->authenticateConfidentialClient($request, $credentials);

        if ($this->isRefreshTokenHint($request)) {
            $payload = $inspector->refreshTokenPayload($tokenValue);

            if ($payload !== null && (string) ($payload->client_id ?? '') === $clientId) {
                $refreshTokenId = $payload->refresh_token_id ?? null;
                $accessTokenId = $payload->access_token_id ?? null;

                if (is_string($refreshTokenId)) {
                    Passport::refreshToken()->newQuery()->whereKey($refreshTokenId)->update(['revoked' => true]);
                }

                if (is_string($accessTokenId)) {
                    Passport::token()->newQuery()->whereKey($accessTokenId)->update(['revoked' => true]);
                }
            }

            return response()->noContent(200);
        }

        $token = $inspector->accessToken($tokenValue);

        if ($token instanceof Token && (string) $token->getAttribute('client_id') === $clientId) {
            $token->revoke();
            Passport::refreshToken()->newQuery()->where('access_token_id', $token->getKey())->update(['revoked' => true]);
        }

        return response()->noContent(200);
    }
}
