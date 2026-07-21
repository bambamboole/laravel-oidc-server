<?php
declare(strict_types=1);
use Bambamboole\LaravelOidc\OidcServiceProvider;

it('registers the oidc config', function () {
    expect(config('oidc.token_lifetimes.id_token'))->toBe(3600)
        ->and(config('oidc.routes'))->toBe([
            'prefix' => '',
            'middleware' => [],
        ])
        ->and(config('oidc.handlers'))->toBe([]);
});

it('feeds configured oidc signing keys into passport config', function () {
    config([
        'oidc.private_key' => 'oidc-private-pem',
        'oidc.public_key' => 'oidc-public-pem',
        'passport.private_key' => null,
        'passport.public_key' => null,
    ]);

    (new OidcServiceProvider(app()))->register();

    expect(config('passport.private_key'))->toBe('oidc-private-pem')
        ->and(config('passport.public_key'))->toBe('oidc-public-pem');
});
