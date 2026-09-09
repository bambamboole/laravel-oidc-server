<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class RealmsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->scoped(RealmResolver::class, fn (): RealmResolver => new RouteRealmResolver(new ConfiguredRealmResolver));
        $this->app->scoped(IssuerResolver::class, RealmIssuerResolver::class);
    }

    public function boot(): void
    {
        // Route generation outside a matched route — console commands, queued
        // notifications — has no realm to fall back on; ResolveRealm overrides
        // this per request.
        URL::defaults(['realm' => (string) config('oidc.realm', 'default')]);
    }
}
