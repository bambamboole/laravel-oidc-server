<?php

declare(strict_types=1);

/**
 * The first-party provisioning action keeps the presented client secret out of exception traces
 */

use Bambamboole\LaravelOidc\Server\Clients\Actions\ProvisionFirstPartyClient;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioningException;

it('redacts the existing client credential from exception traces', function () {
    app(ProvisionFirstPartyClient::class)(name: 'First-party app', redirectUris: ['https://app.test/login/callback']);
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
