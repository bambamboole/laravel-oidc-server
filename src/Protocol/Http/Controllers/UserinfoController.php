<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsRequest;
use Bambamboole\LaravelOidc\Server\Scopes\Contracts\ClaimsResolver;
use Bambamboole\LaravelOidc\Server\Scopes\Enums\ClaimsAudience;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\ProtocolClaims;
use Bambamboole\LaravelOidc\Server\Tokens\Contracts\OAuthenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * OpenID Connect Core §5.3. The `sub` is the provider's and must match the
 * id_token's (§5.3.2), so a resolver cannot replace it or any other
 * protocol claim.
 */
class UserinfoController
{
    public function __invoke(Request $request, ClaimsResolver $claims): JsonResponse
    {
        $user = $request->user(config('oidc.auth.api_guard', 'oidc'));

        if (! $user instanceof OAuthenticatable) {
            throw $request->bearerToken() === null
                ? OAuthServerException::bearerRequired()
                : OAuthServerException::invalidToken();
        }

        $token = $user->currentAccessToken();
        $scopes = $token?->scopes() ?? [];

        if (! in_array('openid', $scopes, true)) {
            throw OAuthServerException::insufficientScope();
        }

        $resolved = $claims->resolve(new ClaimsRequest(
            user: $user,
            audience: ClaimsAudience::Userinfo,
            clientId: $token->clientId(),
            scopes: $scopes,
        ));

        return response()->json([
            'sub' => (string) $user->getAuthIdentifier(),
            ...array_filter($resolved, fn (string $name): bool => ! ProtocolClaims::isReserved($name), ARRAY_FILTER_USE_KEY),
        ]);
    }
}
