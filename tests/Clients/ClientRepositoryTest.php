<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;

it('assigns the realm default and optional scopes to a new client', function (): void {
    config(['oidc.clients.default_scopes' => ['openid'], 'oidc.clients.optional_scopes' => ['email']]);

    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);

    expect($client->default_scopes)->toBe(['openid'])
        ->and($client->optional_scopes)->toBe(['email'])
        ->and($client->assignedScopes())->toBe(['openid', 'email'])
        ->and($client->allowsScope('email'))->toBeTrue()
        ->and($client->allowsScope('profile'))->toBeFalse();
});

it('lets a new client request every catalog scope by default', function (): void {
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    expect($client->default_scopes)->toBe([])
        ->and($client->optional_scopes)->toBe(['*'])
        ->and($client->allowsScope('anything'))->toBeTrue();
});

it('lets the personal access client override the realm assignment', function (): void {
    config(['oidc.clients.default_scopes' => ['openid']]);

    $client = app(ClientRepository::class)->createPersonalAccessGrantClient('PAT', [], ['*']);

    expect($client->default_scopes)->toBe([])
        ->and($client->optional_scopes)->toBe(['*']);
});

it('honours a resource-qualified scope assignment only for that resource', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $client->forceFill([
        'default_scopes' => ['openid', 'https://api.internal/orders orders:read'],
        'optional_scopes' => ['https://api.internal/billing *'],
    ])->save();

    expect($client->defaultScopes())->toBe(['openid'])
        ->and($client->defaultScopes(['https://api.internal/orders']))->toBe(['openid', 'orders:read'])
        ->and($client->assignedScopes(['https://api.internal/billing']))->toBe(['openid', '*'])
        ->and($client->allowsScope('orders:read'))->toBeFalse()
        ->and($client->allowsScope('orders:read', ['https://api.internal/orders']))->toBeTrue()
        ->and($client->allowsScope('anything', ['https://api.internal/billing']))->toBeTrue()
        ->and($client->allowsScope('anything', ['https://api.internal/orders']))->toBeFalse();
});
