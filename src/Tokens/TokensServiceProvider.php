<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenRevoker;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\SignedJwtParser;
use Bambamboole\LaravelOidc\Server\Tokens\Contracts\ExchangePolicy;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\AllowlistExchangePolicy;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\TokenExchanger;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\AccessTokenGuard;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Symfony\Component\HttpFoundation\Response;

class TokensServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $apiGuard = (string) config('oidc.auth.api_guard', 'oidc');

        if (! config()->has("auth.guards.{$apiGuard}")) {
            config()->set("auth.guards.{$apiGuard}", [
                'driver' => 'oidc',
                'provider' => (string) config('oidc.auth.provider', 'users'),
            ]);
        }

        Auth::resolved(fn ($auth) => $auth->extend('oidc', fn ($app, $name, array $config): AccessTokenGuard => tap(
            new AccessTokenGuard(
                $app->make(TokenInspector::class),
                $auth->createUserProvider($config['provider'] ?? null),
                $app->make('request'),
            ),
            fn (AccessTokenGuard $guard) => $app->refresh('request', $guard, 'setRequest'),
        )));

        $this->app->singleton(AccessTokenPipeline::class);
        $this->app->bind(SignedJwtParser::class, TokenInspector::class);
        $this->app->singleton(AccessTokenMinter::class, JwtAccessTokenMinter::class);
        $this->app->singleton(AccessTokenRevoker::class, TokenRevoker::class);
        $this->app->singleton(ExchangePolicy::class, AllowlistExchangePolicy::class);
        $this->app->singleton(TokenExchanger::class);

        $this->callAfterResolving(ExceptionHandler::class, function (ExceptionHandler $handler): void {
            if ($handler instanceof Handler) {
                $handler->renderable($this->renderBearerChallenge(...));
            }
        });
    }

    /**
     * RFC 6750 §3: a request a bearer-token guard turned away is answered
     * with a Bearer challenge rather than Laravel's generic 401 — without an
     * error code when no token was presented (§3.1), `invalid_token` when the
     * presented one was rejected.
     */
    private function renderBearerChallenge(AuthenticationException $exception, Request $request): ?Response
    {
        if (! $this->challengesWithBearer($exception->guards())) {
            return null;
        }

        return ($request->bearerToken() === null
            ? OAuthServerException::bearerRequired()
            : OAuthServerException::invalidToken())->getResponse();
    }

    /**
     * The Authenticate middleware reports the default guard as null.
     *
     * @param  list<string|null>  $guards
     */
    private function challengesWithBearer(array $guards): bool
    {
        $apiGuard = (string) config('oidc.auth.api_guard', 'oidc');

        return array_any($guards, function (?string $guard) use ($apiGuard): bool {
            $guard ??= (string) config('auth.defaults.guard');

            return $guard === $apiGuard || config("auth.guards.{$guard}.driver") === 'oidc';
        });
    }
}
