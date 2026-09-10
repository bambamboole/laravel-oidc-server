<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Shared\Authentication\AuthSessionState;

it('starts a fresh amr list, overwriting any previous value', function () {
    session()->put(AuthSessionState::AMR_KEY, ['stale']);

    app(AuthSessionState::class)->start('pwd');

    expect(session()->get(AuthSessionState::AMR_KEY))->toBe(['pwd']);
});

it('initializes the amr list from empty when adding without a prior start', function () {
    app(AuthSessionState::class)->add('otp');

    expect(session()->get(AuthSessionState::AMR_KEY))->toBe(['otp']);
});

it('appends factor methods and de-dupes while preserving order', function () {
    $context = app(AuthSessionState::class);
    $context->start('pwd');
    $context->add('otp');
    $context->add('otp', 'pwd');

    expect(session()->get(AuthSessionState::AMR_KEY))->toBe(['pwd', 'otp']);
});
