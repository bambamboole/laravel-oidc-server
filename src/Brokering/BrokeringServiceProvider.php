<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering;

use Illuminate\Support\ServiceProvider;

class BrokeringServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(SocialProviderRegistry::class);
    }
}
