<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients;

use Bambamboole\LaravelOidc\Server\Clients\Commands\ProvisionClientCommand;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class ClientsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(
            FirstPartyClientConfig::class,
            fn (Application $app): FirstPartyClientConfig => FirstPartyClientConfig::fromSettings($app->make(RealmResolver::class)->current()->clients()),
        );
        $this->app->singleton(FirstPartyClientProvisioner::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([ProvisionClientCommand::class]);
        }
    }
}
