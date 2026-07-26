<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Token\Jwk;
use Bambamboole\LaravelOidc\Server\Token\SigningKeyGenerator;
use Laravel\Passport\Passport;

it('generates a usable keypair with a matching kid', function () {
    $generated = (new SigningKeyGenerator)->generate();

    expect($generated->privateKeyPem)->toContain('BEGIN PRIVATE KEY')
        ->and($generated->publicKeyPem)->toContain('BEGIN PUBLIC KEY')
        ->and($generated->kid)->toBe(Jwk::fromPem($generated->publicKeyPem)['kid']);
});

it('reports whether signing key material is resolvable', function () {
    expect((new SigningKeyGenerator)->hasKeys())->toBeTrue();

    config(['oidc.private_key' => null, 'oidc.public_key' => null, 'passport.private_key' => null, 'passport.public_key' => null]);
    Passport::loadKeysFrom(temporaryTestDirectory('nokeys'));

    expect((new SigningKeyGenerator)->hasKeys())->toBeFalse();
});
