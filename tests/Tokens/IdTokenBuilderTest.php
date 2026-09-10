<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsRequest;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsResolver;
use Bambamboole\LaravelOidc\Server\Shared\Keys\Jwk;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenBuilder;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenRequest;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Workbench\App\Models\User;

function parseUnencrypted(string $jwt): UnencryptedToken
{
    $token = (new Parser(new JoseEncoder))->parse($jwt);

    if (! $token instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $token;
}

/**
 * @param  list<string>  $amr
 */
function makeIdTokenRequest(User $user, ?string $nonce = null, ?int $authTime = null, array $amr = []): IdTokenRequest
{
    return new IdTokenRequest(
        userId: (string) $user->id,
        clientId: 'client-uuid',
        scopes: ['openid', 'email'],
        accessToken: 'access-token-jwt',
        nonce: $nonce,
        authTime: $authTime,
        amr: $amr,
    );
}

it('builds a signed id_token with the required claims', function () {
    config(['app.url' => 'https://op.test']);
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $jwt = app(IdTokenBuilder::class)->build(makeIdTokenRequest($user, nonce: 'n0nce', authTime: 1700000000));

    $parsed = parseUnencrypted($jwt);

    expect($parsed->headers()->get('alg'))->toBe('RS256')
        ->and($parsed->headers()->get('kid'))->toBe(Jwk::fromPem(signingPublicKey())['kid'])
        ->and($parsed->claims()->get('iss'))->toBe('https://op.test/realms/default')
        ->and($parsed->claims()->get('sub'))->toBe((string) $user->id)
        ->and($parsed->claims()->get('aud'))->toBe(['client-uuid'])
        ->and($parsed->claims()->get('azp'))->toBe('client-uuid')
        ->and($parsed->claims()->get('nonce'))->toBe('n0nce')
        ->and($parsed->claims()->get('auth_time'))->toBe(1700000000)
        ->and($parsed->claims()->get('email'))->toBe('m@example.com')
        ->and($parsed->claims()->get('email_verified'))->toBeTrue()
        ->and($parsed->claims()->has('name'))->toBeFalse();

    $accessTokenJwt = 'access-token-jwt';
    $expectedAtHash = rtrim(strtr(base64_encode(substr(hash('sha256', $accessTokenJwt, true), 0, 16)), '+/', '-_'), '=');
    expect($parsed->claims()->get('at_hash'))->toBe($expectedAtHash);

    $valid = (new Validator)->validate($parsed, new SignedWith(
        new Sha256, InMemory::plainText(signingPublicKey()),
    ));
    expect($valid)->toBeTrue();
});

// OIDC Core §2 — the protocol claims are the provider's
it('drops protocol claims a claims resolver tries to emit', function () {
    config(['app.url' => 'https://op.test']);
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    app()->instance(ClaimsResolver::class, new class implements ClaimsResolver
    {
        public function resolve(ClaimsRequest $request): array
        {
            return ['sub' => 'someone-else', 'iss' => 'https://evil.test', 'aud' => ['other'], 'nonce' => 'forged', 'tenant' => 'acme'];
        }
    });

    $parsed = parseUnencrypted(app(IdTokenBuilder::class)->build(makeIdTokenRequest($user, nonce: 'n0nce')));

    expect($parsed->claims()->get('sub'))->toBe((string) $user->id)
        ->and($parsed->claims()->get('iss'))->toBe('https://op.test/realms/default')
        ->and($parsed->claims()->get('aud'))->toBe(['client-uuid'])
        ->and($parsed->claims()->get('nonce'))->toBe('n0nce')
        ->and($parsed->claims()->get('tenant'))->toBe('acme');
});

it('omits nonce and auth_time when not provided', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $jwt = app(IdTokenBuilder::class)->build(makeIdTokenRequest($user));

    $parsed = parseUnencrypted($jwt);
    expect($parsed->claims()->has('nonce'))->toBeFalse()
        ->and($parsed->claims()->has('auth_time'))->toBeFalse();
});

it('emits amr and derived acr when methods are supplied', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $jwt = app(IdTokenBuilder::class)->build(makeIdTokenRequest($user, amr: ['pwd', 'otp']));

    $parsed = parseUnencrypted($jwt);
    expect($parsed->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and($parsed->claims()->get('acr'))->toBe('2');
});

it('emits acr "1" for a single method', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $jwt = app(IdTokenBuilder::class)->build(makeIdTokenRequest($user, amr: ['pwd']));

    expect(parseUnencrypted($jwt)->claims()->get('acr'))->toBe('1');
});

it('omits amr and acr when no methods are supplied', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $jwt = app(IdTokenBuilder::class)->build(makeIdTokenRequest($user));

    $parsed = parseUnencrypted($jwt);
    expect($parsed->claims()->has('amr'))->toBeFalse()
        ->and($parsed->claims()->has('acr'))->toBeFalse();
});
