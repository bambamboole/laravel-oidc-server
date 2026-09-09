<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Keys;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class KeysServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(SigningKeyStore::class, fn (Application $app): SigningKeyStore => $app->make(
            (string) config('oidc.keys.store', EnvSigningKeyStore::class),
        ));
        $this->app->singleton(SigningKeys::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([RotateKeysCommand::class]);
        }
    }
}
