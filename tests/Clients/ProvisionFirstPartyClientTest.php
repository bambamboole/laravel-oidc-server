<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\Actions\ProvisionFirstPartyClient;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioningException;

it('provisions through the public facade', function () {
    $result = app(ProvisionFirstPartyClient::class)(
        name: 'First-party app',
        redirectUris: ['https://app.test/login/callback'],
        postLogoutRedirectUris: ['https://app.test'],
        allowedExchangeAudiences: ['https://api.test/orders'],
    );

    expect($result->wasCreated)->toBeTrue()
        ->and($result->clientId)->toBe((string) $result->client->getKey())
        ->and($result->clientSecret)->toBeString();
});

it('reconciles a verified client credential through the public facade', function () {
    $created = app(ProvisionFirstPartyClient::class)(
        name: 'Old name',
        redirectUris: ['https://old.test/login/callback'],
    );

    $result = app(ProvisionFirstPartyClient::class)(
        name: 'New name',
        redirectUris: ['https://new.test/login/callback'],
        existingClientSecret: $created->clientSecret,
    );

    expect($result->wasCreated)->toBeFalse()
        ->and($result->clientId)->toBe($created->clientId)
        ->and($result->clientSecret)->toBe($created->clientSecret);
});

it('redacts the existing client credential from exception traces', function () {
    app(ProvisionFirstPartyClient::class)(
        name: 'First-party app',
        redirectUris: ['https://app.test/login/callback'],
    );
    $existingClientSecret = 'trace-secret-that-must-be-redacted';

    try {
        app(ProvisionFirstPartyClient::class)(
            name: 'First-party app',
            redirectUris: ['https://app.test/login/callback'],
            existingClientSecret: $existingClientSecret,
        );
    } catch (FirstPartyClientProvisioningException $exception) {
        $traceContainsSecret = false;

        foreach ($exception->getTrace() as $frame) {
            $arguments = $frame['args'] ?? [];

            array_walk_recursive(
                $arguments,
                function (mixed $argument) use (&$traceContainsSecret, $existingClientSecret): void {
                    $traceContainsSecret = $traceContainsSecret || $argument === $existingClientSecret;
                },
            );
        }

        expect($traceContainsSecret)->toBeFalse();

        return;
    }

    test()->fail('Expected credential verification to fail.');
});
