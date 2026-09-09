<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Keys\StoredSigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Keys\GeneratedSigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Keys\Jwk;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKey;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenBuilder;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenRequest;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Workbench\App\Models\User;

function escapedFixtureKey(string $file): string
{
    return str_replace("\n", '\n', trim((string) file_get_contents(__DIR__.'/../fixtures/'.$file)));
}

it('resolves keys from oidc config with escaped newlines', function () {
    config(['oidc.public_key' => escapedFixtureKey('oauth-public.key')]);

    expect(signingPublicKey())
        ->toBe(trim((string) file_get_contents(__DIR__.'/../fixtures/oauth-public.key')));
});

it('falls back to key files when no config key is set', function () {
    config(['oidc.public_key' => null, 'passport.public_key' => null]);

    expect(signingPublicKey())
        ->toBe(file_get_contents(__DIR__.'/../fixtures/oauth-public.key'));
});

it('fails loud when neither config key nor key file exists', function () {
    config(['oidc.private_key' => null, 'passport.private_key' => null]);
    config(['oidc.keys.path' => '/nonexistent']);

    signingPrivateKey();
})->throws(RuntimeException::class, 'OIDC_PRIVATE_KEY');

it('serves the same jwks from an env-provided key', function () {
    $fromFile = Jwk::fromPem((string) file_get_contents(__DIR__.'/../fixtures/oauth-public.key'));

    config(['oidc.public_key' => escapedFixtureKey('oauth-public.key')]);

    $this->getJson('/realms/default/.well-known/jwks.json')
        ->assertOk()
        ->assertJsonPath('keys.0.kid', $fromFile['kid']);
});

it('signs id_tokens with env-provided keys', function () {
    config([
        'oidc.private_key' => escapedFixtureKey('oauth-private.key'),
        'oidc.public_key' => escapedFixtureKey('oauth-public.key'),
    ]);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $jwt = app(IdTokenBuilder::class)->build(new IdTokenRequest(
        userId: (string) $user->id,
        clientId: 'client-uuid',
        scopes: ['openid'],
        accessToken: 'access-token-jwt',
    ));

    $parsed = (new Parser(new JoseEncoder))->parse($jwt);
    $valid = (new Validator)->validate($parsed, new SignedWith(
        new Sha256,
        InMemory::plainText(signingPublicKey()),
    ));

    expect($valid)->toBeTrue()
        ->and($parsed->headers()->get('kid'))
        ->toBe(Jwk::fromPem(signingPublicKey())['kid']);
});

it('reads every key through the store it was given', function () {
    $keys = new StoredSigningKeys(new class implements SigningKeyStore
    {
        public function signingKey(): SigningKey
        {
            return new SigningKey('custom-public', 'custom-private', 'custom-kid');
        }

        public function verificationKeys(): array
        {
            return [$this->signingKey(), new SigningKey('old-public', null, 'old-kid')];
        }

        public function rotate(GeneratedSigningKeys $keys): void {}
    });

    expect($keys->signingKey()->publicKeyPem)->toBe('custom-public')
        ->and($keys->signingKey()->privateKey())->toBe('custom-private')
        ->and($keys->signingKid())->toBe('custom-kid')
        ->and(array_map(
            fn (SigningKey $key): string => $key->publicKeyPem,
            $keys->verificationKeys(),
        ))->toBe(['custom-public', 'old-public']);
});
