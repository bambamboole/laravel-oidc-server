<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class RealmsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(RealmRepository::class, ConfiguredRealmRepository::class);
        $this->app->singleton(RealmResolver::class, fn (Application $app): RealmResolver => new RouteRealmResolver(
            $app->make(RealmRepository::class),
            new ConfiguredRealmResolver($app->make(RealmRepository::class)),
        ));
        $this->app->singleton(IssuerResolver::class, RealmIssuerResolver::class);
    }

    public function boot(): void
    {
        // Route generation outside a matched route — console commands, queued
        // notifications — has no realm to fall back on; ResolveRealm overrides
        // this per request.
        URL::defaults(['realm' => (string) config('oidc.realm', 'default')]);
    }
}
