<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\BackChannel;

use Illuminate\Support\ServiceProvider;

class BackChannelServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(BackChannelLogoutNotifier::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([DispatchExpiredSessionLogoutsCommand::class]);
        }
    }
}
