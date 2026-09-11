<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

use Bambamboole\LaravelOidc\Server\Realms\Enums\RealmRouting;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class RealmsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(RealmRepository::class, ConfiguredRealmRepository::class);
        $this->app->singleton(RealmResolver::class, function (Application $app): RealmResolver {
            $repository = $app->make(RealmRepository::class);
            $configured = new ConfiguredRealmResolver($repository);

            return RealmRouting::configured() === RealmRouting::Domain
                ? new DomainRealmResolver($repository, $configured)
                : new RouteRealmResolver($repository, $configured);
        });
        $this->app->singleton(IssuerResolver::class, RealmIssuerResolver::class);
    }

    public function boot(): void
    {
        // Route generation outside a matched route — console commands, queued
        // notifications — has no realm to fall back on; ResolveRealm overrides
        // this per request.
        URL::defaults(['realm' => (string) config('oidc.realm', 'default')]);

        Queue::before(fn () => $this->app->make(ResolveRealmForJob::class)());
    }
}
