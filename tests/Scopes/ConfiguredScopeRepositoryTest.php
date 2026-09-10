<?php

declare(strict_types=1);

/**
 * Scope catalog contract: OIDC standard scopes plus the configured catalog (inline map or ScopeCatalog class),
 * per-realm catalogs, fail-open on catalog errors
 */

use Bambamboole\LaravelOidc\Server\Realms\ConfiguredRealm;
use Bambamboole\LaravelOidc\Server\Scopes\ConfiguredScopeRepository;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\Realm;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Shared\Scopes\ScopeCatalog;

class RepositoryClassCatalog implements ScopeCatalog
{
    public function scopes(): array
    {
        return ['catalog:read' => 'Read catalog things'];
    }
}

class RepositoryThrowingCatalog implements ScopeCatalog
{
    public function scopes(): array
    {
        throw new RuntimeException('database is away');
    }
}

/** A catalog whose scopes differ per realm, as one backed by realm-scoped rows would. */
class RepositoryRealmCatalog implements ScopeCatalog
{
    public function scopes(): array
    {
        $realm = app(RealmResolver::class)->current()->id();

        return ["{$realm}:read" => "Read {$realm} things"];
    }
}

/** One resolver instance whose realm can be switched, as a host-derived resolver does between requests. */
class RepositorySwitchableRealmResolver implements RealmResolver
{
    public function __construct(public string $realm) {}

    public function current(): Realm
    {
        return new ConfiguredRealm($this->realm);
    }
}

function freshScopeRepository(): ScopeRepository
{
    return new ConfiguredScopeRepository(app(), app(RealmResolver::class));
}

/** @return list<string> */
function scopeIds(): array
{
    return freshScopeRepository()->all()->map(fn (Scope $scope): string => $scope->id)->all();
}

it('exposes the configured catalog plus the oidc standard scopes, preferring the catalog description', function () {
    config(['oidc.scopes.catalog' => ['project:update' => 'Update projects', 'openid' => 'Custom openid description']]);

    $repository = freshScopeRepository();

    expect(scopeIds())->toContain('project:update', 'openid', 'profile', 'email', 'address', 'phone')
        ->and($repository->all()->filter(fn (Scope $scope): bool => $scope->id === 'openid'))->toHaveCount(1)
        ->and($repository->find('openid')?->description)->toBe('Custom openid description')
        ->and($repository->find('nope'))->toBeNull();
});

it('resolves a class-string catalog from the container and rejects one that does not implement the contract', function () {
    config()->set('oidc.scopes.catalog', RepositoryClassCatalog::class);

    expect(scopeIds())->toContain('catalog:read');

    config()->set('oidc.scopes.catalog', stdClass::class);

    expect(fn () => freshScopeRepository()->all())->toThrow(LogicException::class);
});

it('caches the catalog per realm on one instance', function () {
    config()->set('oidc.scopes.catalog', RepositoryRealmCatalog::class);
    $resolver = new RepositorySwitchableRealmResolver('acme');
    app()->instance(RealmResolver::class, $resolver);
    $repository = new ConfiguredScopeRepository(app(), $resolver);

    expect($repository->find('acme:read'))->not->toBeNull();

    $resolver->realm = 'globex';

    expect($repository->find('globex:read'))->not->toBeNull()
        ->and($repository->find('acme:read'))->toBeNull();

    $resolver->realm = 'acme';

    expect($repository->find('acme:read'))->not->toBeNull();
});

it('falls back to the standard scopes when the catalog throws', function () {
    config()->set('oidc.scopes.catalog', RepositoryThrowingCatalog::class);

    expect(scopeIds())->toContain('openid')->not->toContain('catalog:read');
});
