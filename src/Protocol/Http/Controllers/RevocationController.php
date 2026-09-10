<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Protocol\Clients\ClientAuthenticator;
use Bambamboole\LaravelOidc\Server\Tokens\Events\TokenRevoked;
use Bambamboole\LaravelOidc\Server\Tokens\PresentedToken;
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
        private readonly TokenRevoker $revoker,
        private readonly PresentedTokenResolver $tokens,
    ) {}

    public function __invoke(Request $request, ClientAuthenticator $clients): Response
    {
        $client = $clients->authenticate($request);
        $presented = $this->tokens->fromRequest($request);

        if (! $presented instanceof PresentedToken || ! $presented->accessToken->issuedTo($client)) {
            return response()->noContent(200);
        }

        $this->revoker->revoke($presented->accessToken->id);

        event(new TokenRevoked(
            clientId: $client->client_id,
            tokenType: $presented->isRefreshToken() ? 'refresh_token' : 'access_token',
            jti: $presented->accessToken->id,
            refreshTokenJti: $presented->refreshToken?->id,
        ));

        return response()->noContent(200);
    }
}
