<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Session\SessionTokenGuard;

it('uses an explicit session_token.guard when configured', function () {
    config([
        'oidc.session_token.guard' => 'admin',
        'oidc.auth.guard' => 'identity',
        'auth.defaults.guard' => 'web',
    ]);

    expect(SessionTokenGuard::name())->toBe('admin');
});

it('falls back to the oidc auth guard when session_token.guard is null', function () {
    config([
        'oidc.session_token.guard' => null,
        'oidc.auth.guard' => 'identity',
        'auth.defaults.guard' => 'web',
    ]);

    expect(SessionTokenGuard::name())->toBe('identity');
});

it('falls back to the application default guard when both oidc guards are null', function () {
    config([
        'oidc.session_token.guard' => null,
        'oidc.auth.guard' => null,
        'auth.defaults.guard' => 'web',
    ]);

    expect(SessionTokenGuard::name())->toBe('web');
});

it('treats an empty session_token.guard as no owner', function () {
    config([
        'oidc.session_token.guard' => '',
        'oidc.auth.guard' => 'identity',
        'auth.defaults.guard' => 'web',
    ]);

    expect(SessionTokenGuard::name())->toBeNull();
});
