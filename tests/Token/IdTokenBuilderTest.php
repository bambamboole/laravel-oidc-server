<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Token\IdTokenBuilder;
use Bambamboole\LaravelOidc\Token\Jwk;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\Scope;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\CryptKey;
use Workbench\App\Models\User;

function parseUnencrypted(string $jwt): UnencryptedToken
{
    $token = (new Parser(new JoseEncoder))->parse($jwt);

    if (! $token instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $token;
}

function makeAccessToken(User $user): AccessToken
{
    $client = new Client('client-uuid', 'RP', ['https://rp.test/callback']);
    $token = new class((string) $user->id, [new Scope('openid'), new Scope('email')], $client) extends AccessToken
    {
        private ?string $serialized = null;

        public function toString(): string
        {
            return $this->serialized ??= parent::toString();
        }
    };
    $token->setIdentifier('token-id');
    $token->setExpiryDateTime(new DateTimeImmutable('+1 hour'));
    $token->setPrivateKey(new CryptKey(
        __DIR__.'/../fixtures/oauth-private.key', null, false,
    ));

    return $token;
}

it('builds a signed id_token with the required claims', function () {
    config(['app.url' => 'https://op.test']);
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $accessToken = makeAccessToken($user);

    $jwt = app(IdTokenBuilder::class)->build($accessToken, 'n0nce', 1700000000);

    $parsed = parseUnencrypted($jwt);

    expect($parsed->headers()->get('alg'))->toBe('RS256')
        ->and($parsed->headers()->get('kid'))->toBe(Jwk::fromPem(SigningKeys::publicKey())['kid'])
        ->and($parsed->claims()->get('iss'))->toBe('https://op.test')
        ->and($parsed->claims()->get('sub'))->toBe((string) $user->id)
        ->and($parsed->claims()->get('aud'))->toBe(['client-uuid'])
        ->and($parsed->claims()->get('azp'))->toBe('client-uuid')
        ->and($parsed->claims()->get('nonce'))->toBe('n0nce')
        ->and($parsed->claims()->get('auth_time'))->toBe(1700000000)
        ->and($parsed->claims()->get('email'))->toBe('m@example.com')
        ->and($parsed->claims()->get('email_verified'))->toBeTrue()
        ->and($parsed->claims()->has('name'))->toBeFalse();

    $accessTokenJwt = $accessToken->toString();
    $expectedAtHash = rtrim(strtr(base64_encode(substr(hash('sha256', $accessTokenJwt, true), 0, 16)), '+/', '-_'), '=');
    expect($parsed->claims()->get('at_hash'))->toBe($expectedAtHash);

    $valid = (new Validator)->validate($parsed, new SignedWith(
        new Sha256, InMemory::plainText(SigningKeys::publicKey()),
    ));
    expect($valid)->toBeTrue();
});

it('omits nonce and auth_time when not provided', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $jwt = app(IdTokenBuilder::class)->build(makeAccessToken($user), null, null);

    $parsed = parseUnencrypted($jwt);
    expect($parsed->claims()->has('nonce'))->toBeFalse()
        ->and($parsed->claims()->has('auth_time'))->toBeFalse();
});

it('emits amr and derived acr when methods are supplied', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $jwt = app(IdTokenBuilder::class)->build(makeAccessToken($user), null, null, ['pwd', 'otp']);

    $parsed = parseUnencrypted($jwt);
    expect($parsed->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and($parsed->claims()->get('acr'))->toBe('2');
});

it('emits acr "1" for a single method', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $jwt = app(IdTokenBuilder::class)->build(makeAccessToken($user), null, null, ['pwd']);

    expect(parseUnencrypted($jwt)->claims()->get('acr'))->toBe('1');
});

it('omits amr and acr when no methods are supplied', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $jwt = app(IdTokenBuilder::class)->build(makeAccessToken($user), null, null);

    $parsed = parseUnencrypted($jwt);
    expect($parsed->claims()->has('amr'))->toBeFalse()
        ->and($parsed->claims()->has('acr'))->toBeFalse();
});
