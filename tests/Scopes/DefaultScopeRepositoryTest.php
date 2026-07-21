<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Scopes\DefaultScopeRepository;
use Bambamboole\LaravelOidc\Scopes\Scope;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\ClientEntityInterface;

beforeEach(fn () => $this->repository = new DefaultScopeRepository);

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
