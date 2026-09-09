<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Keys\EnvSigningKeyStore;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeyStore;

it('exposes per-flow lifetime defaults', function () {
    expect(config('oidc.token_lifetimes.access_token'))->toBe(900)
        ->and(config('oidc.token_lifetimes.id_token'))->toBe(3600)
        ->and(config('oidc.token_lifetimes.client_credentials'))->toBe(3600)
        ->and(config('oidc.session.absolute_lifetime'))->toBe(2592000);
});

it('ships an empty scope catalog by default', function () {
    expect(config()->has('oidc.scopes'))->toBeTrue()
        ->and(config('oidc.scopes.catalog'))->toBe([]);
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

it('defaults the signing key store to the env store', function () {
    expect(config('oidc.keys.store'))->toBe(EnvSigningKeyStore::class)
        ->and(app(SigningKeyStore::class)::class)->toBe(EnvSigningKeyStore::class);
});
