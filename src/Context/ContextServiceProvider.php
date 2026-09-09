<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Context;

use Illuminate\Support\ServiceProvider;

class ContextServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(AuthenticationContextStore::class);
        $this->app->singleton(AccessTokenContextLink::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([PruneAuthenticationContextsCommand::class]);
        }
    }
}
