<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Contracts\SessionTokenProvider;
use Bambamboole\LaravelOidc\Server\Facades\Oidc;
use Bambamboole\LaravelOidc\Server\Token\AccessTokenMinter;

it('registers hooks without signing keys and without resolving the token graph', function () {
    config([
        'oidc.private_key' => null,
        'oidc.public_key' => null,
        'passport.private_key' => null,
        'passport.public_key' => null,
    ]);

    Oidc::createUsersUsing(fn () => null);

    expect(app()->resolved(AccessTokenMinter::class))->toBeFalse()
        ->and(app()->resolved(SessionTokenProvider::class))->toBeFalse();
});
