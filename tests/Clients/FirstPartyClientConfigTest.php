<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Clients\FirstPartyClientConfig;

it('resolves the new first-party client configuration', function () {
    config([
        'oidc.first_party' => ['client_id' => 'new-client', 'trusted' => true],
        'oidc.trusted_clients' => ['additional-client'],
    ]);

    $config = FirstPartyClientConfig::fromConfig();

    expect($config->clientId())->toBe('new-client')
        ->and($config->isConfigured())->toBeTrue()
        ->and($config->isTrusted('new-client'))->toBeTrue()
        ->and($config->isTrusted('additional-client'))->toBeTrue();
});

it('makes first-party trust authoritative when its id overlaps the additional trusted list', function () {
    config([
        'oidc.first_party' => ['client_id' => 'first-party-client', 'trusted' => false],
        'oidc.trusted_clients' => ['first-party-client', 'additional-client'],
    ]);

    $config = FirstPartyClientConfig::fromConfig();

    expect($config->clientId())->toBe('first-party-client')
        ->and($config->isTrusted('first-party-client'))->toBeFalse()
        ->and($config->isTrusted('additional-client'))->toBeTrue();
});
