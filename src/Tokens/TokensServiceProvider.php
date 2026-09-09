<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenRevoker;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\SignedJwtParser;
use Bambamboole\LaravelOidc\Server\Tokens\Context\AccessTokenContextLink;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\DefaultExchangePolicy;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\ExchangePolicy;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\TokenExchanger;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\OidcAccessTokenGuard;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class TokensServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $apiGuard = (string) config('oidc.api_guard', 'oidc');

        if (! config()->has("auth.guards.{$apiGuard}")) {
            config()->set("auth.guards.{$apiGuard}", [
                'driver' => 'oidc',
                'provider' => (string) config('oidc.auth.provider', 'users'),
            ]);
        }

        Auth::resolved(fn ($auth) => $auth->extend('oidc', fn ($app, $name, array $config): OidcAccessTokenGuard => tap(
            new OidcAccessTokenGuard(
                $app->make(TokenInspector::class),
                $auth->createUserProvider($config['provider'] ?? null),
                $app->make('request'),
            ),
            fn (OidcAccessTokenGuard $guard) => $app->refresh('request', $guard, 'setRequest'),
        )));

        $this->app->singleton(AccessTokenPipeline::class);
        $this->app->singleton(AccessTokenContextLink::class);
        $this->app->bind(SignedJwtParser::class, TokenInspector::class);
        $this->app->singleton(AccessTokenMinter::class, JwtAccessTokenMinter::class);
        $this->app->singleton(AccessTokenRevoker::class, StoredAccessTokenRevoker::class);
        $this->app->singleton(ExchangePolicy::class, DefaultExchangePolicy::class);
        $this->app->singleton(TokenExchanger::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([PurgeTokensCommand::class]);
        }
    }
}
