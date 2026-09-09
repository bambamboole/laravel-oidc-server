<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Bridge\Client as BridgeClient;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Facades\Oidc;
use Bambamboole\LaravelOidc\Server\Scopes\BridgeScope;
use Bambamboole\LaravelOidc\Server\Scopes\BridgeScopeRepository as PassportBridgeScopeRepository;
use Workbench\App\Models\User;

it('is bound over passport\'s bridge scope repository', function () {
    $resolved = app(PassportBridgeScopeRepository::class);

    expect(get_class($resolved))->toBe('Bambamboole\\LaravelOidc\\Server\\Scopes\\BridgeScopeRepository');
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
    Oidc::tokensCan(['project:update' => 'Update projects']);
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
    $token = $result->token;

    expect($token->getAttribute('scopes'))->toBe(['*']);
});
