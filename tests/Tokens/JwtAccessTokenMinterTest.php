<?php

declare(strict_types=1);

/**
 * RFC 9068 (JWT profile for OAuth 2.0 access tokens)
 */

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Shared\Keys\Jwk;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\MintedAccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\TokenInspector;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Workbench\App\Models\User;

beforeEach(function () {
    config(['app.url' => 'https://op.test']);
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://rp.test/cb']);
});

/**
 * @param  string[]  $scopes
 * @param  string[]  $audiences
 * @param  array<string, mixed>  $extraClaims
 * @param  array<string, mixed>|null  $actor
 */
function mintAccessToken(Client $client, User $user, array $scopes = ['openid', 'email'], array $audiences = [], array $extraClaims = [], ?array $actor = null): MintedAccessToken
{
    return app(AccessTokenMinter::class)->mint((string) $user->id, $client->client_id, $scopes, new DateInterval('PT1H'), $audiences, $extraClaims, $actor);
}

it('emits an RFC 9068 at+jwt access token', function () {
    $minted = mintAccessToken($this->client, $this->user);
    $parsed = parseAccessToken($minted->jwt);

    expect($parsed->headers()->get('typ'))->toBe('at+jwt')
        ->and($parsed->headers()->get('kid'))->toBe(Jwk::fromPem(signingPublicKey())['kid'])
        ->and($parsed->claims()->get('iss'))->toBe('https://op.test/realms/default')
        ->and($parsed->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($parsed->claims()->get('client_id'))->toBe($this->client->client_id)
        ->and($parsed->claims()->get('aud'))->toBe([$this->client->client_id])
        ->and($parsed->claims()->get('scope'))->toBe('openid email')
        ->and($parsed->claims()->get('scopes'))->toBe(['openid', 'email'])
        ->and($parsed->claims()->get('jti'))->toBe($minted->jti)
        ->and($parsed->claims()->has('iat'))->toBeTrue()
        ->and($parsed->claims()->has('nbf'))->toBeTrue()
        ->and($parsed->claims()->has('exp'))->toBeTrue();
});

it('signs with the realm key so the token validates against jwks', function () {
    $parsed = parseAccessToken(mintAccessToken($this->client, $this->user)->jwt);

    expect((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(signingPublicKey()))))->toBeTrue();
});

it('persists the token record the inspector resolves', function () {
    $minted = mintAccessToken($this->client, $this->user);

    $record = app(TokenInspector::class)->accessToken($minted->jwt);

    expect($record)->not->toBeNull()
        ->and((string) $record->getAttribute('user_id'))->toBe((string) $this->user->id)
        ->and((string) $record->getAttribute('client_id'))->toBe((string) $this->client->getKey())
        ->and($record->getAttribute('scopes'))->toBe(['openid', 'email'])
        ->and((bool) $record->getAttribute('revoked'))->toBeFalse();
});

it('uses an explicitly set audience instead of the client id', function () {
    $minted = mintAccessToken($this->client, $this->user, audiences: ['https://api.internal/orders', 'https://api.internal/billing']);

    expect(parseAccessToken($minted->jwt)->claims()->get('aud'))->toBe(['https://api.internal/orders', 'https://api.internal/billing'])
        ->and($minted->audience)->toBe(['https://api.internal/orders', 'https://api.internal/billing']);
});

it('falls back to the client id as subject for a userless token', function () {
    $minted = app(AccessTokenMinter::class)->mint(null, $this->client->client_id, [], new DateInterval('PT1H'));

    expect(parseAccessToken($minted->jwt)->claims()->get('sub'))->toBe($this->client->client_id)
        ->and($minted->userId)->toBeNull();
});

it('does not let extra claims override protected access-token claims', function () {
    $minted = mintAccessToken($this->client, $this->user, extraClaims: [
        'scope' => 'forged',
        'scopes' => ['forged'],
        'client_id' => 'forged-client',
        'cnf' => ['jkt' => 'forged'],
        'act' => ['client_id' => 'forged-client'],
        'sid' => 'forged',
        'tier' => 'gold',
    ]);

    $parsed = parseAccessToken($minted->jwt);

    expect($parsed->claims()->get('scope'))->toBe('openid email')
        ->and($parsed->claims()->get('scopes'))->toBe(['openid', 'email'])
        ->and($parsed->claims()->get('client_id'))->toBe($this->client->client_id)
        ->and($parsed->claims()->has('cnf'))->toBeFalse()
        ->and($parsed->claims()->has('act'))->toBeFalse()
        ->and($parsed->claims()->has('sid'))->toBeFalse()
        ->and($parsed->claims()->get('tier'))->toBe('gold');
});

it('emits the actor claim', function () {
    $minted = mintAccessToken($this->client, $this->user, actor: ['client_id' => 'trusted']);

    expect(parseAccessToken($minted->jwt)->claims()->get('act'))->toBe(['client_id' => 'trusted']);
});

it('refuses to mint for an unknown or revoked client', function () {
    $this->client->forceFill(['revoked' => true])->save();

    expect(fn () => mintAccessToken($this->client, $this->user))->toThrow(RuntimeException::class);
});
