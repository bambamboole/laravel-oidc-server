<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Claims\ClaimsAudience;
use Bambamboole\LaravelOidc\Server\Claims\ClaimsRequest;
use Bambamboole\LaravelOidc\Server\Claims\ClaimsResolver;
use Bambamboole\LaravelOidc\Server\Http\OAuthError;
use Bambamboole\LaravelOidc\Server\User\OAuthenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class UserinfoController
{
    public function __invoke(Request $request, ClaimsResolver $claims): JsonResponse
    {
        $user = $request->user(config('oidc.api_guard', 'oidc'));

        if (! $user instanceof OAuthenticatable) {
            OAuthError::bearer('invalid_token', 401, withRealm: true);
        }

        $token = $user->currentAccessToken();
        $scopes = $token?->scopes() ?? [];

        if (! in_array('openid', $scopes, true)) {
            OAuthError::bearer('insufficient_scope', 403, withRealm: true);
        }

        return response()->json(array_merge(
            ['sub' => (string) $user->getAuthIdentifier()],
            $claims->resolve(new ClaimsRequest(
                user: $user,
                audience: ClaimsAudience::Userinfo,
                clientId: $token->clientId(),
                scopes: $scopes,
            )),
        ));
    }
}
