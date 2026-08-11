<?php

declare(strict_types=1);

it('exposes per-flow lifetime defaults', function () {
    expect(config('oidc.token_lifetimes.access_token'))->toBe(900)
        ->and(config('oidc.token_lifetimes.id_token'))->toBe(3600)
        ->and(config('oidc.token_lifetimes.client_credentials'))->toBe(3600)
        ->and(config('oidc.session.absolute_lifetime'))->toBe(2592000);
});

it('ships empty passport seams by default', function () {
    expect(config()->has('oidc.passport'))->toBeTrue()
        ->and(config('oidc.passport.token_model'))->toBeNull()
        ->and(config('oidc.passport.scopes'))->toBe([]);
});

it('ships no protected resources and disabled dynamic client registration by default', function () {
    expect(config('oidc.protected_resources'))->toBe([])
        ->and(config('oidc.dcr'))->toBe([
            'enabled' => false,
            'allowed_redirect_schemes' => [],
            'allowed_redirect_domains' => ['*'],
            'default_scopes' => [],
        ]);
});
