<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Controllers;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Clients\ClientAuthenticator;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Bambamboole\LaravelOidc\Server\Tokens\TokenInspector;
use Bambamboole\LaravelOidc\Server\Tokens\TokenRevoker;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * RFC 7009. A token that is unknown or belongs to another client is ignored
 * with a 200, so the endpoint never confirms whether a token existed.
 */
class RevocationController
{
    public function __construct(
        private readonly Auditor $auditor,
        private readonly TokenRevoker $revoker,
    ) {}

    public function __invoke(Request $request, ClientAuthenticator $clients, TokenInspector $inspector): Response
    {
        $client = $clients->authenticate($request);
        $tokenValue = (string) $request->input('token');

        if ($request->input('token_type_hint') === 'refresh_token') {
            $this->revokeRefreshToken($tokenValue, $client);
        } else {
            $this->revokeAccessToken($tokenValue, $client, $inspector);
        }

        return response()->noContent(200);
    }

    private function revokeAccessToken(string $tokenValue, Client $client, TokenInspector $inspector): void
    {
        $token = $inspector->accessToken($tokenValue);

        if (! $token instanceof Token || ! $token->issuedTo($client)) {
            return;
        }

        $this->revoker->revoke($token->id);

        $this->auditor->log(AuditEventType::TokenRevoked, clientId: $client->client_id, context: [
            'token_type_hint' => 'access_token',
            'jti' => $token->id,
        ]);
    }

    private function revokeRefreshToken(string $tokenValue, Client $client): void
    {
        $refreshToken = RefreshToken::query()
            ->with('accessToken')
            ->whereIn('access_token_id', Token::query()->inRealm()->select('id'))
            ->find($tokenValue);
        $accessToken = $refreshToken?->accessToken;

        if (! $refreshToken instanceof RefreshToken || ! $accessToken instanceof Token || ! $accessToken->issuedTo($client)) {
            return;
        }

        $this->revoker->revoke($accessToken->id);

        $this->auditor->log(AuditEventType::TokenRevoked, clientId: $client->client_id, context: [
            'token_type_hint' => 'refresh_token',
            'refresh_token_jti' => $refreshToken->id,
            'jti' => $accessToken->id,
        ]);
    }
}
