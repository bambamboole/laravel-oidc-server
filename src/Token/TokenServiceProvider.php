<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Token;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class TokenServiceProvider extends ServiceProvider
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

        $this->app->singleton(AccessTokenMinter::class);
        $this->app->singleton(TokenLifetimes::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([PurgeTokensCommand::class]);
        }
    }
}
