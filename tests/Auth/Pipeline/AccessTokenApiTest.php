<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenApi;

it('records denial state and reason', function () {
    $api = new AccessTokenApi;

    expect($api->isDenied())->toBeFalse()
        ->and($api->denyReason())->toBeNull();

    $api->deny('blocked-client');

    expect($api->isDenied())->toBeTrue()
        ->and($api->denyReason())->toBe('blocked-client');
});

it('buffers custom access-token claims', function () {
    $api = new AccessTokenApi;

    $api->setAccessTokenClaim('tier', 'gold');

    expect($api->accessTokenClaims())->toBe(['tier' => 'gold']);
});

it('refuses protected access-token claim :dataset', function (string $claim) {
    $api = new AccessTokenApi;

    $api->setAccessTokenClaim($claim, 'forged');

    expect($api->accessTokenClaims())->toBe([]);
})->with([
    'iss',
    'sub',
    'aud',
    'exp',
    'iat',
    'nbf',
    'jti',
    'nonce',
    'at_hash',
    'c_hash',
    'auth_time',
    'azp',
    'acr',
    'amr',
    'sid',
    'client_id',
    'scope',
    'scopes',
    'cnf',
    'act',
]);
