<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Shared\Scopes\ScopeCatalog;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Collection;
use LogicException;

class ConfiguredScopeRepository implements ScopeRepository
{
    private const array OIDC_SCOPES = [
        'openid' => 'Authenticate with your account',
        'profile' => 'Access your basic profile information',
        'email' => 'Access your email address',
        'address' => 'Access your postal address',
        'phone' => 'Access your phone number',
    ];

    /** @var array<string, array<string, string>> keyed by realm id */
    private array $catalogs = [];

    public function __construct(
        private readonly Application $app,
        private readonly RealmResolver $realms,
    ) {}

    public function all(): Collection
    {
        return collect($this->catalog())
            ->union(self::OIDC_SCOPES)
            ->map(fn (string $description, string $id): Scope => new Scope($id, $description))
            ->values();
    }

    /**
     * The current realm's configured catalog. A catalog class is resolved once
     * per realm and instance because it may query the database — and per
     * realm, not per instance, because under Octane one instance serves every
     * realm. Its failures fall back to an empty catalog (fail-closed: unknown
     * scopes are stripped at issuance) instead of breaking the flow. An inline
     * array is read fresh each time.
     *
     * @return array<string, string>
     */
    private function catalog(): array
    {
        $realm = $this->realms->current();

        if (isset($this->catalogs[$realm->id()])) {
            return $this->catalogs[$realm->id()];
        }

        $configured = $realm->scopes()->catalog;

        if (! is_string($configured)) {
            return $configured;
        }

        $catalog = $this->app->make($configured);

        if (! $catalog instanceof ScopeCatalog) {
            throw new LogicException("The configured scope catalog [{$configured}] must implement ScopeCatalog.");
        }

        return $this->catalogs[$realm->id()] = rescue(fn (): array => $catalog->scopes(), [], report: ! $this->app->runningInConsole());
    }

    public function find(string $identifier): ?Scope
    {
        return $this->all()->first(fn (Scope $scope): bool => $scope->id === $identifier);
    }

    public function finalize(array $requested, string $grantType, ?Client $client, ?string $userIdentifier = null): array
    {
        return array_values(array_filter(
            $requested,
            fn (Scope $scope): bool => $this->find($scope->id) instanceof Scope,
        ));
    }
}
