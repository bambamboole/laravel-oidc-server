<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Middleware;

use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\AccessTokenBearer;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\AccessTokenGuard;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Enforces that the current bearer token is addressed to one of the given resource audiences.
 * Depends on `auth:oidc` (or any guard that populates `currentAccessToken()`) running first — this
 * middleware performs no independent parsing, signature verification, or revocation check anymore,
 * that is {@see AccessTokenGuard}'s job. It only reads the
 * verified audience the guard stashed on the request and narrows it to the audiences given here.
 * A token meant for another resource is an invalid token here (RFC 6750 §3.1), not one short of
 * a scope.
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

        if (! $user instanceof AccessTokenBearer || $user->currentAccessToken() === null) {
            throw OAuthServerException::invalidToken();
        }

        $tokenAudiences = (array) $request->attributes->get('oidc_token_audience', []);

        if (array_intersect($audiences, $tokenAudiences) === []) {
            throw OAuthServerException::invalidToken('The access token is not addressed to this resource.');
        }

        return $next($request);
    }
}
