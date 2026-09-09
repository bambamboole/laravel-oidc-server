<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\User;

use Illuminate\Support\ServiceProvider;

class UserServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(UserActionManager::class);
    }
}
