<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Keys;

use Bambamboole\LaravelOidc\Server\Keys\Commands\RotateKeysCommand;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyStore;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class KeysServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(SigningKeyStore::class, fn (Application $app): SigningKeyStore => $app->make(
            (string) config('oidc.keys.store', EnvSigningKeyStore::class),
        ));
        $this->app->singleton(SigningKeys::class, StoredSigningKeys::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([RotateKeysCommand::class]);
        }
    }
}
