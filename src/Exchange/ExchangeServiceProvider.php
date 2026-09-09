<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Exchange;

use Illuminate\Support\ServiceProvider;

class ExchangeServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ExchangePolicy::class, DefaultExchangePolicy::class);
        $this->app->singleton(TokenExchanger::class);
    }
}
