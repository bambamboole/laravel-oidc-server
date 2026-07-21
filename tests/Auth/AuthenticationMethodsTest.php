<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\AuthenticationMethods;

it('starts a fresh amr list, overwriting any previous value', function () {
    session()->put(AuthenticationMethods::SESSION_KEY, ['stale']);

    app(AuthenticationMethods::class)->start('pwd');

    expect(session()->get(AuthenticationMethods::SESSION_KEY))->toBe(['pwd']);
});

it('initializes the amr list from empty when adding without a prior start', function () {
    app(AuthenticationMethods::class)->add('otp');

    expect(session()->get(AuthenticationMethods::SESSION_KEY))->toBe(['otp']);
});

it('appends factor methods and de-dupes while preserving order', function () {
    $context = app(AuthenticationMethods::class);
    $context->start('pwd');
    $context->add('otp');
    $context->add('otp', 'pwd');

    expect(session()->get(AuthenticationMethods::SESSION_KEY))->toBe(['pwd', 'otp']);
});

it('derives acr from the number of methods', function () {
    expect(AuthenticationMethods::deriveAcr([]))->toBeNull()
        ->and(AuthenticationMethods::deriveAcr(['pwd']))->toBe('1')
        ->and(AuthenticationMethods::deriveAcr(['pwd', 'otp']))->toBe('2')
        ->and(AuthenticationMethods::deriveAcr(['pwd', 'webauthn']))->toBe('2');
});
