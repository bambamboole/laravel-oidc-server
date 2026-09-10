<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Middleware;

use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\AccessTokenBearer;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\CurrentAccessToken;
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

        if (! $user instanceof AccessTokenBearer || ! $user->currentAccessToken() instanceof CurrentAccessToken) {
            throw OAuthServerException::invalidToken();
        }

        foreach ($scopes as $scope) {
            if (! $user->currentAccessToken()->can($scope)) {
                throw OAuthServerException::insufficientScope();
            }
        }

        return $next($request);
    }
}
