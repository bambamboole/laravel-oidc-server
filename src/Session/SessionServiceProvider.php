<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Session;

use Illuminate\Support\ServiceProvider;

class SessionServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(SessionTokenProvider::class, SessionMintTokenProvider::class);
        $this->app->singleton(OidcSessionRepository::class);
    }
}
