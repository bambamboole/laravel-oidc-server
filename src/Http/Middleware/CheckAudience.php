<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Middleware;

use Bambamboole\LaravelOidc\Server\Http\OAuthError;
use Bambamboole\LaravelOidc\Server\Token\OidcAccessTokenGuard;
use Closure;
use Illuminate\Http\Request;
use Laravel\Passport\Contracts\OAuthenticatable;
use Symfony\Component\HttpFoundation\Response;

/**
 * Enforces that the current bearer token is addressed to one of the given resource audiences.
 * Depends on `auth:oidc` (or any guard that populates `currentAccessToken()`) running first — this
 * middleware performs no independent parsing, signature verification, or revocation check anymore,
 * that is {@see OidcAccessTokenGuard}'s job. It only reads the
 * verified audience the guard stashed on the request and narrows it to the audiences given here.
 */
class CheckAudience
{
    public static function using(string ...$audiences): string
    {
        return static::class.':'.implode(',', $audiences);
    }

    public function handle(Request $request, Closure $next, string ...$audiences): Response
    {
        $user = $request->user();

        if (! $user instanceof OAuthenticatable || $user->currentAccessToken() === null) {
            OAuthError::bearer('invalid_token', 401);
        }

        $tokenAudiences = (array) $request->attributes->get('oidc_token_audience', []);

        if (array_intersect($audiences, $tokenAudiences) === []) {
            OAuthError::bearer('insufficient_scope', 403);
        }

        return $next($request);
    }
}
