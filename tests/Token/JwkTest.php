<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Token\Jwk;

it('derives a JWK from a PEM public key', function () {
    $jwk = Jwk::fromPem(file_get_contents(__DIR__.'/../fixtures/oauth-public.key'));

    expect($jwk)->toHaveKeys(['kty', 'use', 'alg', 'kid', 'n', 'e'])
        ->and($jwk['kty'])->toBe('RSA')
        ->and($jwk['use'])->toBe('sig')
        ->and($jwk['alg'])->toBe('RS256')
        ->and($jwk['n'])->not->toContain('+', '/', '=')
        ->and($jwk['e'])->toBe('AQAB');
});

it('computes an RFC 7638 thumbprint as the kid', function () {
    $jwk = Jwk::fromPem(file_get_contents(__DIR__.'/../fixtures/oauth-public.key'));

    $expected = rtrim(strtr(base64_encode(hash(
        'sha256',
        json_encode(['e' => $jwk['e'], 'kty' => 'RSA', 'n' => $jwk['n']]),
        true,
    )), '+/', '-_'), '=');

    expect($jwk['kid'])->toBe($expected);
});

it('rejects non-RSA keys', function () {
    Jwk::fromPem('not a key');
})->throws(RuntimeException::class);

it('derives the same JWK from a PKCS#1 public key', function () {
    $pkcs8 = Jwk::fromPem(file_get_contents(__DIR__.'/../fixtures/oauth-public.key'));
    $pkcs1 = Jwk::fromPem(file_get_contents(__DIR__.'/../fixtures/oauth-public.pkcs1.key'));

    expect($pkcs1)->toBe($pkcs8);
});

it('tolerates surrounding whitespace in the PEM', function () {
    $pem = file_get_contents(__DIR__.'/../fixtures/oauth-public.key');

    expect(Jwk::fromPem("\n  ".trim($pem)."\n\n"))->toBe(Jwk::fromPem($pem));
});

it('rejects EC public keys', function () {
    Jwk::fromPem(file_get_contents(__DIR__.'/../fixtures/ec-public.key'));
})->throws(RuntimeException::class, 'Only RSA public keys');
