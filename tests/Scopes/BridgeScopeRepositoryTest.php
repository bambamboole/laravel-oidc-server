<?php

declare(strict_types=1);

use Laravel\Passport\Bridge\Client as BridgeClient;
use Laravel\Passport\Bridge\Scope as BridgeScope;
use Laravel\Passport\Bridge\ScopeRepository as PassportBridgeScopeRepository;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use Workbench\App\Models\User;

it('is bound over passport\'s bridge scope repository', function () {
    $resolved = app(PassportBridgeScopeRepository::class);

    expect(get_class($resolved))->toBe('Bambamboole\\LaravelOidc\\Scopes\\BridgeScopeRepository');
});

it('resolves oidc scopes that passport does not know', function () {
    $entity = app(PassportBridgeScopeRepository::class)->getScopeEntityByIdentifier('openid');

    expect($entity)->not->toBeNull()
        ->and($entity->getIdentifier())->toBe('openid');
});

it('returns null for unknown scopes', function () {
    expect(app(PassportBridgeScopeRepository::class)->getScopeEntityByIdentifier('nope'))->toBeNull();
});

it('finalizes scopes through the contract', function () {
    Passport::tokensCan(['project:update' => 'Update projects']);
    $client = new BridgeClient('client-id', 'Test', ['https://rp.test/callback']);

    $finalized = app(PassportBridgeScopeRepository::class)->finalizeScopes(
        [new BridgeScope('openid'), new BridgeScope('project:update'), new BridgeScope('nope')],
        'authorization_code',
        $client,
        '1',
    );

    expect(collect($finalized)->map->getIdentifier()->all())->toBe(['openid', 'project:update']);
});

it('resolves the wildcard scope like passport does', function () {
    $entity = app(PassportBridgeScopeRepository::class)->getScopeEntityByIdentifier('*');

    expect($entity)->not->toBeNull()
        ->and($entity->getIdentifier())->toBe('*');
});

it('keeps the wildcard scope for exempt grant types', function () {
    $client = new BridgeClient('client-id', 'Test', ['https://rp.test/callback']);

    $finalized = app(PassportBridgeScopeRepository::class)->finalizeScopes(
        [new BridgeScope('*')],
        'personal_access',
        $client,
        '1',
    );

    expect(collect($finalized)->map->getIdentifier()->all())->toBe(['*']);
});

it('rejects the wildcard scope for authorization_code finalization', function () {
    $client = new BridgeClient('client-id', 'Test', ['https://rp.test/callback']);

    $finalized = app(PassportBridgeScopeRepository::class)->finalizeScopes(
        [new BridgeScope('openid'), new BridgeScope('*')],
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
    $token = $result->getToken();

    expect($token)->toBeInstanceOf(Token::class);
    expect($token->getAttribute('scopes'))->toBe(['*']);
});
