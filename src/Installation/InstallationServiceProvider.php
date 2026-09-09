<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Installation;

use Bambamboole\LaravelOidc\Server\Shared\Installation\EnvironmentFile;
use Illuminate\Support\ServiceProvider;

class InstallationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(EnvironmentFile::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([InstallSelfCommand::class]);
        }
    }
}
