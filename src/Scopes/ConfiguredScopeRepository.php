<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Scopes\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Shared\Scopes\ScopeCatalog;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\RealmAudiences;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Collection;
use LogicException;

class ConfiguredScopeRepository implements ScopeRepository
{
    private const array OIDC_SCOPES = [
        'openid' => 'Authenticate with your account',
        'profile' => 'Access your basic profile information',
        'email' => 'Access your email address',
    ];

    /** @var array<string, array<string, string>> keyed by realm id and audience set */
    private array $catalogs = [];

    public function __construct(
        private readonly Application $app,
        private readonly RealmResolver $realms,
        private readonly RealmAudiences $audiences,
    ) {}

    public function all(array $audiences = []): Collection
    {
        return collect($this->catalog($this->audiences->resolve($audiences)))
            ->union(self::OIDC_SCOPES)
            ->map(fn (string $description, string $id): Scope => new Scope($id, $description))
            ->values();
    }

    public function find(string $identifier, array $audiences = []): ?Scope
    {
        return $this->all($audiences)->first(fn (Scope $scope): bool => $scope->id === $identifier);
    }

    public function finalize(array $requested, string $grantType, ?Client $client, ?string $userIdentifier = null, array $audiences = []): array
    {
        return array_values(array_filter(
            $requested,
            fn (Scope $scope): bool => $this->find($scope->id, $audiences) instanceof Scope,
        ));
    }

    /**
     * The scopes the requested resources own: what each of them declares in
     * the realm's resource settings, plus the realm's own catalog when the
     * realm itself is among them. A catalog class is asked for the audiences
     * directly and owns that split itself.
     *
     * @param  list<string>  $audiences
     * @return array<string, string>
     */
    private function catalog(array $audiences): array
    {
        $configured = $this->realms->current()->scopes()->catalog;
        $declared = $this->audiences->declaredScopes($audiences);

        if (is_string($configured)) {
            return $this->fromClass($configured, $audiences) + array_fill_keys($declared, '');
        }

        $realmOwned = in_array($this->audiences->default()[0], $audiences, true)
            ? array_diff_key($configured, array_flip($this->audiences->claimedScopes()))
            : [];

        return $realmOwned + array_intersect_key($configured, array_flip($declared)) + array_fill_keys($declared, '');
    }

    /**
     * A catalog class is resolved once per realm, audience set and instance
     * because it may query the database — and per realm, not per instance,
     * because under Octane one instance serves every realm. Its failures fall
     * back to an empty catalog (fail-closed: unknown scopes are stripped at
     * issuance) instead of breaking the flow.
     *
     * @param  list<string>  $audiences
     * @return array<string, string>
     */
    private function fromClass(string $configured, array $audiences): array
    {
        sort($audiences);
        $key = $this->realms->current()->identifier()."\n".implode("\n", $audiences);

        if (isset($this->catalogs[$key])) {
            return $this->catalogs[$key];
        }

        $catalog = $this->app->make($configured);

        if (! $catalog instanceof ScopeCatalog) {
            throw new LogicException("The configured scope catalog [{$configured}] must implement ScopeCatalog.");
        }

        return $this->catalogs[$key] = rescue(fn (): array => $catalog->scopes($audiences), [], report: ! $this->app->runningInConsole());
    }
}
