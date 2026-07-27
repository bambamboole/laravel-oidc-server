<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

use Bambamboole\LaravelOidc\Server\Contracts\ScopeCatalog;
use Bambamboole\LaravelOidc\Server\Contracts\ScopeRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Collection;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use LogicException;

class DefaultScopeRepository implements ScopeRepository
{
    private const array OIDC_SCOPES = [
        'openid' => 'Authenticate with your account',
        'profile' => 'Access your basic profile information',
        'email' => 'Access your email address',
        'address' => 'Access your postal address',
        'phone' => 'Access your phone number',
    ];

    /** @var array<string, string>|null */
    private ?array $catalog = null;

    public function __construct(private readonly Application $app) {}

    public function all(): Collection
    {
        return collect($this->catalog())
            ->union(Passport::$scopes)
            ->union(self::OIDC_SCOPES)
            ->map(fn (string $description, string $id) => new Scope($id, $description))
            ->values();
    }

    /**
     * The configured catalog, resolved once per instance. A catalog may query
     * the database, so failures fall back to an empty catalog (fail-closed:
     * unknown scopes are stripped at issuance) instead of breaking the flow.
     *
     * @return array<string, string>
     */
    private function catalog(): array
    {
        if ($this->catalog !== null) {
            return $this->catalog;
        }

        $configured = config('oidc.passport.scopes', []);

        if (is_string($configured)) {
            $catalog = $this->app->make($configured);

            if (! $catalog instanceof ScopeCatalog) {
                throw new LogicException("The configured scope catalog [{$configured}] must implement ScopeCatalog.");
            }

            $configured = rescue(fn (): array => $catalog->scopes(), [], report: ! $this->app->runningInConsole());
        }

        return $this->catalog = is_array($configured) ? $configured : [];
    }

    public function find(string $identifier): ?Scope
    {
        return $this->all()->first(fn (Scope $scope) => $scope->id === $identifier);
    }

    public function finalize(array $requested, string $grantType, ClientEntityInterface $client, ?string $userIdentifier = null): array
    {
        return array_values(array_filter(
            $requested,
            fn (Scope $scope) => $this->find($scope->id) instanceof Scope,
        ));
    }
}
