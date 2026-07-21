<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Token\IdTokenBuilder;
use Bambamboole\LaravelOidc\Token\Jwk;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\Bridge\Client as BridgeClient;
use Laravel\Passport\Bridge\Scope as BridgeScope;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\CryptKey;
use Workbench\App\Models\User;

function escapedFixtureKey(string $file): string
{
    return str_replace("\n", '\n', trim((string) file_get_contents(__DIR__.'/../fixtures/'.$file)));
}

it('resolves keys from oidc config with escaped newlines', function () {
    config(['oidc.public_key' => escapedFixtureKey('oauth-public.key')]);

    expect(SigningKeys::publicKey())
        ->toBe(trim((string) file_get_contents(__DIR__.'/../fixtures/oauth-public.key')));
});

it('prefers the oidc config key over the passport config key', function () {
    config([
        'oidc.public_key' => escapedFixtureKey('oauth-public.key'),
        'passport.public_key' => 'stale-passport-key',
    ]);

    expect(SigningKeys::publicKey())
        ->toBe(trim((string) file_get_contents(__DIR__.'/../fixtures/oauth-public.key')));
});

it('falls back to the passport config key when no oidc key is set', function () {
    config([
        'oidc.public_key' => null,
        'passport.public_key' => escapedFixtureKey('oauth-public.key'),
    ]);

    expect(SigningKeys::publicKey())
        ->toBe(trim((string) file_get_contents(__DIR__.'/../fixtures/oauth-public.key')));
});

it('falls back to key files when no config key is set', function () {
    config(['oidc.public_key' => null, 'passport.public_key' => null]);

    expect(SigningKeys::publicKey())
        ->toBe(file_get_contents(__DIR__.'/../fixtures/oauth-public.key'));
});

it('fails loud when neither config key nor key file exists', function () {
    config(['oidc.private_key' => null, 'passport.private_key' => null]);
    Passport::loadKeysFrom('/nonexistent');

    SigningKeys::privateKey();
})->throws(RuntimeException::class, 'OIDC_PRIVATE_KEY');

it('serves the same jwks from an env-provided key', function () {
    $fromFile = Jwk::fromPem((string) file_get_contents(__DIR__.'/../fixtures/oauth-public.key'));

    config(['oidc.public_key' => escapedFixtureKey('oauth-public.key')]);

    $this->getJson('/.well-known/jwks.json')
        ->assertOk()
        ->assertJsonPath('keys.0.kid', $fromFile['kid']);
});

it('signs id_tokens with env-provided keys', function () {
    config([
        'oidc.private_key' => escapedFixtureKey('oauth-private.key'),
        'oidc.public_key' => escapedFixtureKey('oauth-public.key'),
    ]);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $client = new BridgeClient('client-uuid', 'RP', ['https://rp.test/callback']);
    $accessToken = new AccessToken((string) $user->id, [new BridgeScope('openid')], $client);
    $accessToken->setIdentifier('env-token-id');
    $accessToken->setExpiryDateTime(new DateTimeImmutable('+1 hour'));
    $accessToken->setPrivateKey(new CryptKey(__DIR__.'/../fixtures/oauth-private.key', null, false));

    $jwt = app(IdTokenBuilder::class)->build($accessToken, null, null);

    $parsed = (new Parser(new JoseEncoder))->parse($jwt);
    $valid = (new Validator)->validate($parsed, new SignedWith(
        new Sha256,
        InMemory::plainText(SigningKeys::publicKey()),
    ));

    expect($valid)->toBeTrue()
        ->and($parsed->headers()->get('kid'))
        ->toBe(Jwk::fromPem(SigningKeys::publicKey())['kid']);
});
