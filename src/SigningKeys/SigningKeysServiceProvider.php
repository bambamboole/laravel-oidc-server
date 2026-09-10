<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\SigningKeys;

use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\Keyring;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\SigningKeys\Commands\RotateKeysCommand;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class SigningKeysServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(SigningKeyStore::class, fn (Application $app): SigningKeyStore => $app->make(
            (string) config('oidc.keys.store', DatabaseSigningKeyStore::class),
        ));
        $this->app->singleton(Keyring::class, StoredKeyring::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([RotateKeysCommand::class]);
        }
    }
}
