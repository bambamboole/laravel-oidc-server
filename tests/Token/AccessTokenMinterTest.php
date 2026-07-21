<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Token\AccessTokenMinter;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Bambamboole\LaravelOidc\Token\TokenInspector;
use Laravel\Passport\ClientRepository;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Workbench\App\Models\User;

function parseMinted(string $jwt): UnencryptedToken
{
    $parsed = (new Parser(new JoseEncoder))->parse($jwt);

    if (! $parsed instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $parsed;
}

it('mints, signs and persists a scoped at+jwt that round-trips', function () {
    config(['app.url' => 'https://op.test']);
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://rp.test/cb']);

    $entity = app(AccessTokenMinter::class)->mint(
        (string) $user->id, $client, ['openid', 'email'], new DateInterval('PT1H'), ['https://api.test'],
    );

    $jwt = $entity->toString();
    $parsed = parseMinted($jwt);

    expect($parsed->headers()->get('typ'))->toBe('at+jwt')
        ->and($parsed->claims()->get('iss'))->toBe('https://op.test')
        ->and($parsed->claims()->get('sub'))->toBe((string) $user->id)
        ->and($parsed->claims()->get('client_id'))->toBe($client->id)
        ->and($parsed->claims()->get('aud'))->toBe(['https://api.test'])
        ->and($parsed->claims()->get('scope'))->toBe('openid email');

    expect((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(SigningKeys::publicKey()))))->toBeTrue();

    $dbToken = app(TokenInspector::class)->accessToken($jwt);
    expect($dbToken)->not->toBeNull()
        ->and((string) $dbToken->getAttribute('user_id'))->toBe((string) $user->id)
        ->and((bool) $dbToken->getAttribute('revoked'))->toBeFalse();
});

it('defaults the audience to the client id when none given', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://rp.test/cb']);

    $entity = app(AccessTokenMinter::class)->mint((string) $user->id, $client, ['openid'], new DateInterval('PT1H'));

    expect(parseMinted($entity->toString())->claims()->get('aud'))->toBe([$client->id]);
});
