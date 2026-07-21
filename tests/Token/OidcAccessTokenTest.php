<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Token\Jwk;
use Bambamboole\LaravelOidc\Token\OidcAccessToken;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\Scope;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\CryptKey;

/** @param string[] $scopeIds */
function makeOidcAccessToken(array $scopeIds = ['openid', 'email']): OidcAccessToken
{
    $client = new Client('client-uuid', 'RP', ['https://rp.test/cb']);
    $token = new OidcAccessToken('42', array_map(fn ($s) => new Scope($s), $scopeIds), $client);
    $token->setIdentifier('token-id');
    $token->setExpiryDateTime(new DateTimeImmutable('+1 hour'));
    $token->setPrivateKey(new CryptKey(__DIR__.'/../fixtures/oauth-private.key', null, false));

    return $token;
}

it('emits an RFC 9068 at+jwt access token', function () {
    config(['app.url' => 'https://op.test']);
    $parsed = parseAccessToken(makeOidcAccessToken()->toString());

    expect($parsed->headers()->get('typ'))->toBe('at+jwt')
        ->and($parsed->headers()->get('kid'))->toBe(Jwk::fromPem(SigningKeys::publicKey())['kid'])
        ->and($parsed->claims()->get('iss'))->toBe('https://op.test')
        ->and($parsed->claims()->get('sub'))->toBe('42')
        ->and($parsed->claims()->get('client_id'))->toBe('client-uuid')
        ->and($parsed->claims()->get('aud'))->toBe(['client-uuid'])
        ->and($parsed->claims()->get('scope'))->toBe('openid email')
        ->and($parsed->claims()->get('jti'))->toBe('token-id')
        ->and($parsed->claims()->has('iat'))->toBeTrue()
        ->and($parsed->claims()->has('nbf'))->toBeTrue()
        ->and($parsed->claims()->has('exp'))->toBeTrue();
});

it('keeps the legacy scopes array claim alongside the scope string', function () {
    $parsed = parseAccessToken(makeOidcAccessToken()->toString());

    expect($parsed->claims()->get('scopes'))->toBe(['openid', 'email']);
});

it('uses an explicitly set audience instead of the client id', function () {
    $token = makeOidcAccessToken();
    $token->setAudience('https://api.internal/orders', 'https://api.internal/billing');

    $parsed = parseAccessToken($token->toString());

    expect($parsed->claims()->get('aud'))->toBe(['https://api.internal/orders', 'https://api.internal/billing']);
});

it('signs with the passport key so the token validates against jwks', function () {
    $parsed = parseAccessToken(makeOidcAccessToken()->toString());

    expect((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(SigningKeys::publicKey()))))->toBeTrue();
});

it('memoizes serialization', function () {
    $token = makeOidcAccessToken();
    expect($token->toString())->toBe($token->toString());
});

it('does not let extra claims override protected access-token claims', function () {
    $token = makeOidcAccessToken();
    $token->addExtraClaim('scope', 'forged');
    $token->addExtraClaim('scopes', ['forged']);
    $token->addExtraClaim('client_id', 'forged-client');
    $token->addExtraClaim('cnf', ['jkt' => 'forged']);
    $token->addExtraClaim('act', ['client_id' => 'forged-client']);
    $token->addExtraClaim('sid', 'forged');

    $parsed = parseAccessToken($token->toString());

    expect($parsed->claims()->get('scope'))->toBe('openid email')
        ->and($parsed->claims()->get('scopes'))->toBe(['openid', 'email'])
        ->and($parsed->claims()->get('client_id'))->toBe('client-uuid')
        ->and($parsed->claims()->has('cnf'))->toBeFalse()
        ->and($parsed->claims()->has('act'))->toBeFalse()
        ->and($parsed->claims()->has('sid'))->toBeFalse();
});

it('emits a package-owned actor claim', function () {
    $token = makeOidcAccessToken();
    $token->setActor(['client_id' => 'trusted']);

    $parsed = parseAccessToken($token->toString());

    expect($parsed->claims()->get('act'))->toBe(['client_id' => 'trusted']);
});
