<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Middleware;

use Bambamboole\LaravelOidc\Server\Contracts\OAuthenticatable;
use Bambamboole\LaravelOidc\Server\Http\OAuthError;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires every listed scope on the token backing the request. Runs after a
 * guard that populates currentAccessToken() — `auth:oidc`, in practice.
 */
class CheckScopes
{
    public static function using(string ...$scopes): string
    {
        return static::class.':'.implode(',', $scopes);
    }

    public function handle(Request $request, Closure $next, string ...$scopes): Response
    {
        $user = $request->user();

        if (! $user instanceof OAuthenticatable || $user->currentAccessToken() === null) {
            OAuthError::bearer('invalid_token', 401);
        }

        foreach ($scopes as $scope) {
            if (! $user->currentAccessToken()->can($scope)) {
                OAuthError::bearer('insufficient_scope', 403);
            }
        }

        return $next($request);
    }
}
