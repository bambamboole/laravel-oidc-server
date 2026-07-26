<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Support;

use Bambamboole\LaravelOidc\Contracts\ScopeCatalog;
use Bambamboole\LaravelOidc\Contracts\ScopeRepository;
use Illuminate\Contracts\Foundation\Application;
use Laravel\Passport\Passport;
use LogicException;

class PassportConfigurator
{
    public function __construct(private readonly Application $app) {}

    public function __invoke(): void
    {
        $tokenModel = config('oidc.passport.token_model');

        if (is_string($tokenModel) && $tokenModel !== '') {
            Passport::useTokenModel($tokenModel);
        }

        $scopes = config('oidc.passport.scopes', []);

        if (is_string($scopes)) {
            // A catalog may query the database, so it is materialized only
            // when scope enumeration is actually needed — consent, discovery,
            // and issuance all resolve the ScopeRepository; unrelated
            // requests never pay for it.
            $this->app->afterResolving(ScopeRepository::class, fn () => $this->materialize($scopes));

            return;
        }

        // tokensCan() replaces Passport's whole scope list, so an empty or
        // failed catalog must leave scopes another provider registered untouched.
        if (is_array($scopes) && $scopes !== []) {
            Passport::tokensCan($scopes);
        }
    }

    private function materialize(string $class): void
    {
        $catalog = $this->app->make($class);

        if (! $catalog instanceof ScopeCatalog) {
            throw new LogicException("The configured scope catalog [{$class}] must implement ScopeCatalog.");
        }

        $scopes = rescue(fn (): array => $catalog->scopes(), [], report: false);

        if ($scopes !== []) {
            Passport::tokensCan($scopes);
        }
    }
}
