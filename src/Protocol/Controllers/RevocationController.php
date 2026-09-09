<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Controllers;

use Bambamboole\LaravelOidc\Server\Clients\ClientCredentials;
use Bambamboole\LaravelOidc\Server\Clients\Concerns\AuthenticatesConfidentialClient;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Bambamboole\LaravelOidc\Server\Tokens\TokenInspector;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class RevocationController
{
    use AuthenticatesConfidentialClient;

    public function __construct(private readonly Auditor $auditor) {}

    public function __invoke(Request $request, ClientCredentials $credentials, TokenInspector $inspector): Response
    {
        [$clientId, $tokenValue] = $this->authenticateConfidentialClient($request, $credentials);

        if ($this->isRefreshTokenHint($request)) {
            $refreshToken = RefreshToken::query()
                ->with('accessToken')
                ->whereIn('access_token_id', Token::query()->inRealm()->select('id'))
                ->find($tokenValue);
            $accessToken = $refreshToken?->accessToken;

            if ($refreshToken instanceof RefreshToken
                && $accessToken instanceof Token
                && (string) $accessToken->getAttribute('client_id') === $clientId) {
                RefreshToken::query()->whereKey($refreshToken->getKey())->update(['revoked' => true]);
                Token::query()->whereKey($accessToken->getKey())->update(['revoked' => true]);

                $this->auditor->log(AuditEventType::TokenRevoked, clientId: $clientId, context: [
                    'token_type_hint' => 'refresh_token',
                    'refresh_token_jti' => (string) $refreshToken->getKey(),
                    'jti' => (string) $accessToken->getKey(),
                ]);
            }

            return response()->noContent(200);
        }

        $token = $inspector->accessToken($tokenValue);

        if ($token instanceof Token && (string) $token->getAttribute('client_id') === $clientId) {
            Token::query()->whereKey($token->getKey())->update(['revoked' => true]);
            RefreshToken::query()->where('access_token_id', $token->getKey())->update(['revoked' => true]);

            $this->auditor->log(AuditEventType::TokenRevoked, clientId: $clientId, context: [
                'token_type_hint' => 'access_token',
                'jti' => (string) $token->getKey(),
            ]);
        }

        return response()->noContent(200);
    }
}
