<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioningException;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioningResult;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Schema;

it('prevents duplicate managed rows as the concurrency backstop', function () {
    expect(Schema::hasColumn('oidc_clients', 'provisioning_key'))->toBeTrue();

    $clients = app(ClientRepository::class);
    $first = $clients->createAuthorizationCodeGrantClient('One', ['https://one.test/callback']);
    $second = $clients->createAuthorizationCodeGrantClient('Two', ['https://two.test/callback']);

    $first->forceFill(['provisioning_key' => 'first-party'])->save();

    expect(fn () => $second->forceFill(['provisioning_key' => 'first-party'])->save())
        ->toThrow(QueryException::class);
});

it('carries the client, one-time secret, and provisioning flags in a readonly result', function () {
    $client = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('First-party app', ['https://app.test/login/callback']);

    $result = new FirstPartyClientProvisioningResult(
        client: $client,
        clientId: (string) $client->getKey(),
        clientSecret: 'plain-secret',
        wasCreated: true,
        secretRotated: false,
    );

    expect($result->client)->toBe($client)
        ->and($result->clientId)->toBe((string) $client->getKey())
        ->and($result->clientSecret)->toBe('plain-secret')
        ->and($result->wasCreated)->toBeTrue()
        ->and($result->secretRotated)->toBeFalse();
});

it('provides a constructible provisioning exception', function () {
    $exception = new FirstPartyClientProvisioningException('Provisioning failed.');

    expect($exception->getMessage())->toBe('Provisioning failed.')
        ->and((new ReflectionClass($exception))->isSubclassOf(RuntimeException::class))->toBeTrue();
});

it('rolls back a created client by deleting it', function () {
    $client = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('First-party app', ['https://app.test/login/callback']);
    $key = $client->getKey();

    $result = new FirstPartyClientProvisioningResult(
        client: $client,
        clientId: (string) $key,
        clientSecret: 'plain-secret',
        wasCreated: true,
        secretRotated: false,
    );

    expect($result->rollback())->toBeTrue()
        ->and(Client::query()->find($key))->toBeNull();
});

it('does not roll back an adopted or reconciled client', function () {
    $client = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Legacy', ['https://legacy.test/callback']);
    $key = $client->getKey();

    $result = new FirstPartyClientProvisioningResult(
        client: $client,
        clientId: (string) $key,
        clientSecret: null,
        wasCreated: false,
        secretRotated: false,
    );

    expect($result->rollback())->toBeFalse()
        ->and(Client::query()->find($key))->not->toBeNull();
});

it('exposes provider env variables with the trusted flag', function () {
    $result = new FirstPartyClientProvisioningResult(
        client: app(ClientRepository::class)
            ->createAuthorizationCodeGrantClient('First-party app', ['https://app.test/login/callback']),
        clientId: 'abc-123',
        clientSecret: 'plain-secret',
        wasCreated: true,
        secretRotated: false,
    );

    expect($result->providerEnvVariables(true))->toBe([
        'OIDC_FIRST_PARTY_CLIENT' => 'abc-123',
        'OIDC_FIRST_PARTY_TRUSTED' => 'true',
    ])->and($result->providerEnvVariables())->toBe([
        'OIDC_FIRST_PARTY_CLIENT' => 'abc-123',
        'OIDC_FIRST_PARTY_TRUSTED' => 'false',
    ]);
});
