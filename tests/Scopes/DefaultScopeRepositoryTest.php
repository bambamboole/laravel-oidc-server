<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Contracts\ScopeCatalog;
use Bambamboole\LaravelOidc\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Scopes\DefaultScopeRepository;
use Bambamboole\LaravelOidc\Scopes\Scope;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\ClientEntityInterface;

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

beforeEach(fn () => $this->repository = new DefaultScopeRepository(app()));

it('exposes passport scopes plus the oidc standard scopes', function () {
    Passport::tokensCan(['project:update' => 'Update projects']);

    $ids = $this->repository->all()->map(fn (Scope $scope) => $scope->id);

    expect($ids->all())->toContain('project:update', 'openid', 'profile', 'email', 'address', 'phone');
});

it('does not duplicate oidc scopes the app already defines', function () {
    Passport::tokensCan(['openid' => 'Custom openid description']);

    expect($this->repository->all()->filter(fn (Scope $scope) => $scope->id === 'openid'))->toHaveCount(1)
        ->and($this->repository->find('openid')->description)->toBe('Custom openid description');
});

it('finds a scope by identifier and returns null for unknown ones', function () {
    expect($this->repository->find('openid'))->toBeInstanceOf(Scope::class)
        ->and($this->repository->find('nope'))->toBeNull();
});

it('finalize drops scopes not in the catalog', function () {
    $client = Mockery::mock(ClientEntityInterface::class);

    $result = $this->repository->finalize(
        [new Scope('openid'), new Scope('unknown')],
        'authorization_code',
        $client,
        '1',
    );

    expect(array_map(fn (Scope $scope) => $scope->id, $result))->toBe(['openid']);
});

it('includes an inline configured scope map', function () {
    config()->set('oidc.passport.scopes', ['inline:scope' => 'Inline']);

    $ids = app(ScopeRepository::class)->all()->map(fn (Scope $scope) => $scope->id);

    expect($ids)->toContain('inline:scope')->toContain('openid');
});

it('includes a class-string catalog resolved from the container', function () {
    config()->set('oidc.passport.scopes', RepositoryCountingCatalog::class);

    $ids = app(ScopeRepository::class)->all()->map(fn (Scope $scope) => $scope->id);

    expect($ids)->toContain('catalog:read');
});

it('resolves the catalog once per repository instance', function () {
    RepositoryCountingCatalog::$calls = 0;
    config()->set('oidc.passport.scopes', RepositoryCountingCatalog::class);

    $repository = app(ScopeRepository::class);
    $repository->all();
    $repository->find('catalog:read');

    expect(RepositoryCountingCatalog::$calls)->toBe(1);
});

it('does not consult the catalog until scopes are enumerated', function () {
    RepositoryCountingCatalog::$calls = 0;
    config()->set('oidc.passport.scopes', RepositoryCountingCatalog::class);

    app(ScopeRepository::class);

    expect(RepositoryCountingCatalog::$calls)->toBe(0);
});

it('prefers a catalog description over tokensCan and built-in oidc scopes', function () {
    config()->set('oidc.passport.scopes', ['profile' => 'Catalog wording', 'api:x' => 'X']);
    Passport::tokensCan(['api:x' => 'Passport wording']);

    $repository = app(ScopeRepository::class);

    expect($repository->find('profile')?->description)->toBe('Catalog wording')
        ->and($repository->find('api:x')?->description)->toBe('X');
});

it('still honours scopes registered through tokensCan', function () {
    Passport::tokensCan(['legacy:scope' => 'Registered directly']);

    expect(app(ScopeRepository::class)->find('legacy:scope'))->not->toBeNull();
});

it('falls back to an empty catalog when the catalog throws', function () {
    config()->set('oidc.passport.scopes', RepositoryThrowingCatalog::class);

    $ids = app(ScopeRepository::class)->all()->map(fn (Scope $scope) => $scope->id);

    expect($ids)->toContain('openid')->not->toContain('catalog:read');
});

it('rejects a catalog class that does not implement the contract', function () {
    config()->set('oidc.passport.scopes', stdClass::class);

    app(ScopeRepository::class)->all();
})->throws(LogicException::class);

it('treats an explicit null scopes config as an empty catalog', function () {
    config()->set('oidc.passport.scopes', null);

    $ids = app(ScopeRepository::class)->all()->map(fn (Scope $scope) => $scope->id);

    expect($ids)->toContain('openid');
});
