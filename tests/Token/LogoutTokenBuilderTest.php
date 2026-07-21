<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Models\OidcSession;
use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Bambamboole\LaravelOidc\Token\LogoutTokenBuilder;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;

function parseUnencryptedLogoutToken(string $jwt): UnencryptedToken
{
    $token = (new Parser(new JoseEncoder))->parse($jwt);

    if (! $token instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $token;
}

it('mints a spec-shaped, signed logout token', function () {
    $sid = app(SessionRegistry::class)->start('99');
    $session = OidcSession::query()->find($sid);

    $jwt = app(LogoutTokenBuilder::class)->build($session, 'client-xyz');
    $token = parseUnencryptedLogoutToken($jwt);

    expect($token->headers()->get('typ'))->toBe('logout+jwt')
        ->and($token->claims()->get('aud'))->toBe(['client-xyz'])
        ->and($token->claims()->get('sub'))->toBe('99')
        ->and($token->claims()->get('sid'))->toBe($sid)
        ->and($token->claims()->has('nonce'))->toBeFalse()
        ->and($token->claims()->get('events'))
        ->toHaveKey('http://schemas.openid.net/event/backchannel-logout')
        ->and((new Validator)->validate($token, new SignedWith(new Sha256, InMemory::plainText(SigningKeys::publicKey()))))
        ->toBeTrue();
});

it('serialises the events claim as a nested empty JSON object', function () {
    $sid = app(SessionRegistry::class)->start('99');
    $session = OidcSession::query()->find($sid);

    $jwt = app(LogoutTokenBuilder::class)->build($session, 'client-xyz');

    [, $payload] = explode('.', $jwt);
    $json = base64_decode(strtr($payload, '-_', '+/'));

    // Assert directly on the raw JSON string so we can't be fooled by
    // json_decode(..., true) collapsing an empty object into an empty array.
    expect($json)->toContain('"events":{"http://schemas.openid.net/event/backchannel-logout":{}}');

    // Also verify via a non-associative decode, which preserves the
    // object/array distinction as stdClass vs array.
    $decoded = json_decode($json, false);
    expect($decoded->events)->toBeInstanceOf(stdClass::class);
    expect($decoded->events->{'http://schemas.openid.net/event/backchannel-logout'})
        ->toBeInstanceOf(stdClass::class);
});
