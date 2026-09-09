<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ClientEntity as BridgeClient;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ScopeEntity;
use Bambamboole\LaravelOidc\Server\Protocol\League\Repositories\ScopeRepository as LeagueScopeRepository;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Workbench\App\Models\User;

it('is bound as the league scope repository', function () {
    expect(get_class(app(ScopeRepositoryInterface::class)))->toBe(LeagueScopeRepository::class);
});

it('resolves oidc scopes that passport does not know', function () {
    $entity = app(LeagueScopeRepository::class)->getScopeEntityByIdentifier('openid');

    expect($entity)->not->toBeNull()
        ->and($entity->getIdentifier())->toBe('openid');
});

it('returns null for unknown scopes', function () {
    expect(app(LeagueScopeRepository::class)->getScopeEntityByIdentifier('nope'))->toBeNull();
});

it('finalizes scopes through the contract', function () {
    config(['oidc.scopes.catalog' => ['project:update' => 'Update projects']]);
    $client = new BridgeClient('client-id', 'Test', ['https://rp.test/callback']);

    $finalized = app(LeagueScopeRepository::class)->finalizeScopes(
        [new ScopeEntity('openid'), new ScopeEntity('project:update'), new ScopeEntity('nope')],
        'authorization_code',
        $client,
        '1',
    );

    expect(collect($finalized)->map->getIdentifier()->all())->toBe(['openid', 'project:update']);
});

it('resolves the wildcard scope like passport does', function () {
    $entity = app(LeagueScopeRepository::class)->getScopeEntityByIdentifier('*');

    expect($entity)->not->toBeNull()
        ->and($entity->getIdentifier())->toBe('*');
});

it('keeps the wildcard scope for exempt grant types', function () {
    $client = new BridgeClient('client-id', 'Test', ['https://rp.test/callback']);

    $finalized = app(LeagueScopeRepository::class)->finalizeScopes(
        [new ScopeEntity('*')],
        'personal_access',
        $client,
        '1',
    );

    expect(collect($finalized)->map->getIdentifier()->all())->toBe(['*']);
});

it('rejects the wildcard scope for authorization_code finalization', function () {
    $client = new BridgeClient('client-id', 'Test', ['https://rp.test/callback']);

    $finalized = app(LeagueScopeRepository::class)->finalizeScopes(
        [new ScopeEntity('openid'), new ScopeEntity('*')],
        'authorization_code',
        $client,
        '1',
    );

    expect(collect($finalized)->map->getIdentifier()->all())->toBe(['openid']);
});

it('issues a personal access token with the wildcard scope', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    app(ClientRepository::class)->createPersonalAccessGrantClient('PAT', 'users');

    $result = $user->createToken('wildcard', ['*']);
    $token = $result->token;

    expect($token->getAttribute('scopes'))->toBe(['*']);
});
