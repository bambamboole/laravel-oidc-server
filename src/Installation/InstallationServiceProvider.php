<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Installation;

use Illuminate\Support\ServiceProvider;

class InstallationServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([InstallSelfCommand::class]);
        }
    }
}
