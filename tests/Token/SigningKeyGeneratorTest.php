<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Token\Jwk;
use Bambamboole\LaravelOidc\Server\Token\SigningKeyGenerator;
use Laravel\Passport\Passport;

it('generates a usable keypair with a matching kid', function () {
    $generated = app(SigningKeyGenerator::class)->generate();

    expect($generated->privateKeyPem)->toContain('BEGIN PRIVATE KEY')
        ->and($generated->publicKeyPem)->toContain('BEGIN PUBLIC KEY')
        ->and($generated->kid)->toBe(Jwk::fromPem($generated->publicKeyPem)['kid']);
});

it('reports whether signing key material is resolvable', function () {
    expect(app(SigningKeyGenerator::class)->hasKeys())->toBeTrue();

    config(['oidc.private_key' => null, 'oidc.public_key' => null, 'passport.private_key' => null, 'passport.public_key' => null]);
    Passport::loadKeysFrom(temporaryTestDirectory('nokeys'));

    expect(app(SigningKeyGenerator::class)->hasKeys())->toBeFalse();
});
