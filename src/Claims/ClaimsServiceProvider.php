<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Claims;

use Illuminate\Support\ServiceProvider;

class ClaimsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ClaimsResolver::class, DefaultClaimsResolver::class);
    }
}
