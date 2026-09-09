<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Scopes\DefaultScopeRepository;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Shared\Scopes\ScopeCatalog;
use Illuminate\Support\Facades\Exceptions;

class RepositoryCountingCatalog implements ScopeCatalog
{
    public static int $calls = 0;

    public function scopes(): array
    {
        static::$calls++;

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

beforeEach(fn () => $this->repository = new DefaultScopeRepository(app(), app(RealmResolver::class)));

it('exposes registered scopes plus the oidc standard scopes', function () {
    config(['oidc.scopes.catalog' => ['project:update' => 'Update projects']]);

    $ids = $this->repository->all()->map(fn (Scope $scope) => $scope->id);

    expect($ids->all())->toContain('project:update', 'openid', 'profile', 'email', 'address', 'phone');
});

it('does not duplicate oidc scopes the app already defines', function () {
    config(['oidc.scopes.catalog' => ['openid' => 'Custom openid description']]);

    expect($this->repository->all()->filter(fn (Scope $scope) => $scope->id === 'openid'))->toHaveCount(1)
        ->and($this->repository->find('openid')->description)->toBe('Custom openid description');
});

it('finds a scope by identifier and returns null for unknown ones', function () {
    expect($this->repository->find('openid'))->toBeInstanceOf(Scope::class)
        ->and($this->repository->find('nope'))->toBeNull();
});

it('finalize drops scopes not in the catalog', function () {
    $result = $this->repository->finalize(
        [new Scope('openid'), new Scope('unknown')],
        'authorization_code',
        null,
        '1',
    );

    expect(array_map(fn (Scope $scope) => $scope->id, $result))->toBe(['openid']);
});

it('includes an inline configured scope map', function () {
    config()->set('oidc.scopes.catalog', ['inline:scope' => 'Inline']);

    $ids = app(ScopeRepository::class)->all()->map(fn (Scope $scope) => $scope->id);

    expect($ids)->toContain('inline:scope')->toContain('openid');
});

it('includes a class-string catalog resolved from the container', function () {
    config()->set('oidc.scopes.catalog', RepositoryCountingCatalog::class);

    $ids = app(ScopeRepository::class)->all()->map(fn (Scope $scope) => $scope->id);

    expect($ids)->toContain('catalog:read');
});

it('resolves the catalog once per repository instance', function () {
    RepositoryCountingCatalog::$calls = 0;
    config()->set('oidc.scopes.catalog', RepositoryCountingCatalog::class);

    $repository = app(ScopeRepository::class);
    $repository->all();
    $repository->find('catalog:read');

    expect(RepositoryCountingCatalog::$calls)->toBe(1);
});

it('does not consult the catalog until scopes are enumerated', function () {
    RepositoryCountingCatalog::$calls = 0;
    config()->set('oidc.scopes.catalog', RepositoryCountingCatalog::class);

    app(ScopeRepository::class);

    expect(RepositoryCountingCatalog::$calls)->toBe(0);
});

it('prefers a catalog description over the built-in oidc scopes', function () {
    config()->set('oidc.scopes.catalog', ['profile' => 'Catalog wording', 'api:x' => 'X']);

    $repository = app(ScopeRepository::class);

    expect($repository->find('profile')?->description)->toBe('Catalog wording')
        ->and($repository->find('api:x')?->description)->toBe('X');
});

it('reads an inline catalog fresh after the repository was resolved', function () {
    $repository = app(ScopeRepository::class);
    config(['oidc.scopes.catalog' => ['legacy:scope' => 'Registered later']]);

    expect($repository->find('legacy:scope'))->not->toBeNull();
});

it('falls back to an empty catalog when the catalog throws', function () {
    config()->set('oidc.scopes.catalog', RepositoryThrowingCatalog::class);

    $ids = app(ScopeRepository::class)->all()->map(fn (Scope $scope) => $scope->id);

    expect($ids)->toContain('openid')->not->toContain('catalog:read');
});

it('suppresses catalog failure reports when running in console', function () {
    Exceptions::fake();
    config()->set('oidc.scopes.catalog', RepositoryThrowingCatalog::class);

    app(ScopeRepository::class)->all();

    Exceptions::assertNothingReported();
});

it('reports catalog failures when not running in console', function () {
    Exceptions::fake();

    // runningInConsole() is cached true under the test runner; flip it so the
    // repository takes the web-request branch that surfaces the failure.
    (new ReflectionProperty($this->app, 'isRunningInConsole'))->setValue($this->app, false);

    config()->set('oidc.scopes.catalog', RepositoryThrowingCatalog::class);

    app(ScopeRepository::class)->all();

    Exceptions::assertReported(RuntimeException::class);
});

it('rejects a catalog class that does not implement the contract', function () {
    config()->set('oidc.scopes.catalog', stdClass::class);

    app(ScopeRepository::class)->all();
})->throws(LogicException::class);

it('treats an explicit null scopes config as an empty catalog', function () {
    config()->set('oidc.scopes.catalog', null);

    $ids = app(ScopeRepository::class)->all()->map(fn (Scope $scope) => $scope->id);

    expect($ids)->toContain('openid');
});
