<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

use Illuminate\Support\ServiceProvider;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

class ScopesServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ScopeRepository::class, DefaultScopeRepository::class);
        $this->app->bind(ScopeRepositoryInterface::class, BridgeScopeRepository::class);
    }
}
