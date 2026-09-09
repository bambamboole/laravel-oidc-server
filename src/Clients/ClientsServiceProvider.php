<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients;

use Illuminate\Support\ServiceProvider;

class ClientsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(
            FirstPartyClientConfig::class,
            fn (): FirstPartyClientConfig => FirstPartyClientConfig::fromConfig(),
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
