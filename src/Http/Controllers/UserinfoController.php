<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http\Controllers;

use Bambamboole\LaravelOidc\Contracts\ClaimsResolver;
use Bambamboole\LaravelOidc\Http\OAuthError;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Passport\AccessToken;
use Laravel\Passport\Contracts\OAuthenticatable;

class UserinfoController
{
    public function __invoke(Request $request, ClaimsResolver $claims): JsonResponse
    {
        $user = $request->user(config('oidc.api_guard', 'api'));

        if (! $user instanceof OAuthenticatable) {
            OAuthError::bearer('invalid_token', 401, withRealm: true);
        }

        $token = $user->currentAccessToken();
        $scopes = $token instanceof AccessToken ? $token->oauth_scopes : [];

        if (! in_array('openid', $scopes, true)) {
            OAuthError::bearer('insufficient_scope', 403, withRealm: true);
        }

        return response()->json(array_merge(
            ['sub' => (string) $user->getAuthIdentifier()],
            $claims->resolve($user)->forScopes($scopes),
        ));
    }
}
