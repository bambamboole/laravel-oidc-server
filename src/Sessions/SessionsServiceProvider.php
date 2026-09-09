<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions;

use Bambamboole\LaravelOidc\Server\Sessions\BackChannel\BackChannelLogoutNotifier;
use Bambamboole\LaravelOidc\Server\Sessions\BackChannel\DispatchExpiredSessionLogoutsCommand;
use Illuminate\Support\ServiceProvider;

class SessionsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(SessionTokenProvider::class, SessionMintTokenProvider::class);
        $this->app->singleton(OidcSessionRepository::class);
        $this->app->singleton(BackChannelLogoutNotifier::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([DispatchExpiredSessionLogoutsCommand::class]);
        }
    }
}
