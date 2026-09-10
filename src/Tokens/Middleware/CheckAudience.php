<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Middleware;

use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\AccessTokenBearer;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\AccessTokenGuard;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\CurrentAccessToken;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Narrows the audience {@see AccessTokenGuard} verified and stashed on the request to the given
 * resource audiences; it parses and verifies nothing itself, so a guard that populates
 * `currentAccessToken()` (`auth:oidc`) must run first. A token meant for another resource is an
 * invalid token here (RFC 6750 §3.1), not one short of a scope.
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

        if (! $user instanceof AccessTokenBearer || ! $user->currentAccessToken() instanceof CurrentAccessToken) {
            throw OAuthServerException::invalidToken();
        }

        $tokenAudiences = (array) $request->attributes->get('oidc_token_audience', []);

        if (array_intersect($audiences, $tokenAudiences) === []) {
            throw OAuthServerException::invalidToken('The access token is not addressed to this resource.');
        }

        return $next($request);
    }
}
