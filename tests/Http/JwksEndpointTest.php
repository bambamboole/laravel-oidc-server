<?php
declare(strict_types=1);

/**
 * RFC 7517 §5 (JWK Set) + RFC 7518 §6.3 (RSA params); RFC 7638 (JWK thumbprint / kid)
 */

use Bambamboole\LaravelOidc\Token\Jwk;

it('serves the public key as a JWKS document', function () {
    $expected = Jwk::fromPem(file_get_contents(__DIR__.'/../fixtures/oauth-public.key'));

    $this->getJson('/.well-known/jwks.json')
        ->assertOk()
        ->assertHeader('Cache-Control', 'max-age=3600, public')
        ->assertJson(['keys' => [$expected]]);
});

it('serves a previous public key alongside the active key during rotation', function () {
    $activeKid = $this->getJson('/.well-known/jwks.json')->json('keys.0.kid');

    $previousPem = file_get_contents(__DIR__.'/../fixtures/retired-public.key');
    $previousKid = Jwk::fromPem($previousPem)['kid'];
    config(['oidc.additional_public_keys' => [$previousPem]]);

    $kids = collect((array) $this->getJson('/.well-known/jwks.json')->json('keys'))->pluck('kid')->all();

    expect($kids)->toContain($activeKid)->toContain($previousKid);
});

it('deduplicates a previous key that equals the active key', function () {
    config(['oidc.additional_public_keys' => [file_get_contents(__DIR__.'/../fixtures/oauth-public.key')]]);

    $this->getJson('/.well-known/jwks.json')->assertJsonCount(1, 'keys');
});
