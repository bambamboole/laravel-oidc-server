<?php

declare(strict_types=1);

/**
 * RFC 9068 §2.1 (at+jwt header), §2.2 (claims: aud names resources, client_id names the client); RFC 8693 §4.1 (act)
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
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

it('emits a signed RFC 9068 at+jwt access token with a persisted record', function () {
    $minted = mintAccessToken($this->client, $this->user);
    $parsed = parseAccessToken($minted->jwt);
    $record = app(TokenInspector::class)->accessToken($minted->jwt);

    expect($parsed->headers()->get('typ'))->toBe('at+jwt')
        ->and($parsed->headers()->get('kid'))->toBe(Jwk::fromPem(signingPublicKey())['kid'])
        ->and($parsed->claims()->get('iss'))->toBe('https://op.test/realms/default')
        ->and($parsed->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($parsed->claims()->get('client_id'))->toBe($this->client->client_id)
        ->and($parsed->claims()->get('aud'))->toBe(['https://op.test/realms/default'])
        ->and($parsed->claims()->get('scope'))->toBe('openid email')
        ->and($parsed->claims()->get('scopes'))->toBe(['openid', 'email'])
        ->and($parsed->claims()->get('jti'))->toBe($minted->jti)
        ->and($parsed->claims()->has('iat'))->toBeTrue()
        ->and($parsed->claims()->has('nbf'))->toBeTrue()
        ->and($parsed->claims()->has('exp'))->toBeTrue()
        ->and((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(signingPublicKey()))))->toBeTrue()
        ->and((string) $record?->getAttribute('user_id'))->toBe((string) $this->user->id)
        ->and((string) $record?->getAttribute('client_id'))->toBe((string) $this->client->getKey())
        ->and($record?->getAttribute('scopes'))->toBe(['openid', 'email'])
        ->and((bool) $record?->getAttribute('revoked'))->toBeFalse();
});

// RFC 9068 §2.2 — aud names the resources the token is for; the client stays in client_id
it('addresses the token to the realm audiences unless an audience is given', function () {
    config(['oidc.tokens.audiences' => ['https://api.example/orders', 'https://api.example/billing']]);

    $defaulted = mintAccessToken($this->client, $this->user);
    $explicit = mintAccessToken($this->client, $this->user, audiences: ['https://api.internal/orders']);

    expect(parseAccessToken($defaulted->jwt)->claims()->get('aud'))->toBe(['https://api.example/orders', 'https://api.example/billing'])
        ->and($defaulted->audience)->toBe(['https://api.example/orders', 'https://api.example/billing'])
        ->and(parseAccessToken($defaulted->jwt)->claims()->get('client_id'))->toBe($this->client->client_id)
        ->and(parseAccessToken($explicit->jwt)->claims()->get('aud'))->toBe(['https://api.internal/orders'])
        ->and($explicit->audience)->toBe(['https://api.internal/orders']);
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

it('refuses to mint for a revoked client', function () {
    $this->client->forceFill(['revoked' => true])->save();

    expect(fn () => mintAccessToken($this->client, $this->user))->toThrow(RuntimeException::class);
});
