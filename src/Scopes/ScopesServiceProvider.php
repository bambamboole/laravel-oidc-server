<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsResolver;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\StandardClaimsResolver;
use Illuminate\Support\ServiceProvider;

class ScopesServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ScopeRepository::class, ConfiguredScopeRepository::class);
        $this->app->singleton(ClaimsResolver::class, StandardClaimsResolver::class);
        $this->app->singleton(ScopeGrant::class);
    }
}
