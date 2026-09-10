<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Controllers;

use Bambamboole\LaravelOidc\Server\Protocol\Clients\ClientAuthenticator;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Tokens\PresentedTokenResolver;
use Bambamboole\LaravelOidc\Server\Tokens\TokenRevoker;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * RFC 7009. A token that is unknown or belongs to another client is ignored
 * with a 200, so the endpoint never confirms whether a token existed. An
 * access token and the refresh token issued alongside it go together (§2.1).
 */
class RevocationController
{
    public function __construct(
        private readonly Auditor $auditor,
        private readonly TokenRevoker $revoker,
        private readonly PresentedTokenResolver $tokens,
    ) {}

    public function __invoke(Request $request, ClientAuthenticator $clients): Response
    {
        $client = $clients->authenticate($request);
        $presented = $this->tokens->fromRequest($request);

        if ($presented === null || ! $presented->accessToken->issuedTo($client)) {
            return response()->noContent(200);
        }

        $this->revoker->revoke($presented->accessToken->id);

        $this->auditor->log(AuditEventType::TokenRevoked, clientId: $client->client_id, context: array_filter([
            'token_type' => $presented->isRefreshToken() ? 'refresh_token' : 'access_token',
            'refresh_token_jti' => $presented->refreshToken?->id,
            'jti' => $presented->accessToken->id,
        ]));

        return response()->noContent(200);
    }
}
