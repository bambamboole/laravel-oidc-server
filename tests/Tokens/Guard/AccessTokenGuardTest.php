<?php

declare(strict_types=1);

/**
 * RFC 6750 §3 (bearer challenges from the auth:oidc guard); RFC 9068 §4 (iss); RFC 9728 §5.1 (resource_metadata)
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Shared\Keys\Jwk;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Workbench\App\Models\User;

const GUARD_RESOURCE_METADATA = 'resource_metadata="http://localhost/.well-known/oauth-protected-resource/realms/default"';

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    Route::middleware('auth:oidc')->get('/guarded', fn () => ['id' => auth()->id()]);
});

/**
 * An otherwise valid at+jwt signed with the realm's key but carrying a foreign
 * issuer, with a persisted row so only the iss check can reject it.
 */
function bearerIssuedElsewhere(mixed $test): string
{
    $jti = Str::random(80);
    $now = new DateTimeImmutable;

    $config = Configuration::forAsymmetricSigner(
        new Sha256,
        InMemory::plainText(signingPrivateKey()),
        InMemory::plainText(signingPublicKey()),
    );

    $jwt = $config->builder()
        ->withHeader('typ', 'at+jwt')
        ->withHeader('kid', Jwk::fromPem(signingPublicKey())['kid'])
        ->issuedBy('https://other-issuer.test/realms/default')
        ->identifiedBy($jti)
        ->issuedAt($now)
        ->canOnlyBeUsedAfter($now)
        ->expiresAt($now->modify('+1 hour'))
        ->relatedTo((string) $test->user->id)
        ->permittedFor((string) $test->client->id)
        ->withClaim('client_id', (string) $test->client->id)
        ->withClaim('scope', 'openid')
        ->getToken($config->signer(), $config->signingKey())
        ->toString();

    (new AccessToken)->forceFill([
        'realm_id' => AccessToken::currentRealm(),
        'id' => $jti,
        'user_id' => $test->user->id,
        'client_id' => $test->client->id,
        'scopes' => ['openid'],
        'revoked' => false,
        'expires_at' => now()->addHour(),
    ])->save();

    return $jwt;
}

it('authenticates a token the realm issued', function () {
    $jwt = resourceServerBearer($this, [(string) $this->client->id]);

    $this->getJson('/guarded', ['Authorization' => "Bearer $jwt"])
        ->assertOk()
        ->assertJson(['id' => $this->user->id]);
});

// RFC 6750 §3.1 — no credentials presented: a challenge without an error code
it('challenges a request without a bearer token and names no error', function () {
    $this->getJson('/guarded')
        ->assertUnauthorized()
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", '.GUARD_RESOURCE_METADATA)
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertNoContent(401);
});

it('answers a rejected bearer token with invalid_token', function () {
    $jwt = resourceServerBearer($this, [(string) $this->client->id], revoked: true);

    $this->getJson('/guarded', ['Authorization' => "Bearer $jwt"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token')
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", error="invalid_token", '.GUARD_RESOURCE_METADATA);
});

it('challenges a browser request instead of redirecting it to login', function () {
    Route::get('/login', fn () => 'login')->name('login');
    Route::getRoutes()->refreshNameLookups();

    $this->get('/guarded')
        ->assertUnauthorized()
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", '.GUARD_RESOURCE_METADATA);
});

// RFC 9068 §4
it('rejects a token whose iss is not the realm issuer', function () {
    $jwt = bearerIssuedElsewhere($this);

    $this->getJson('/guarded', ['Authorization' => "Bearer $jwt"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token');
});

it('leaves other guards to Laravel', function () {
    Route::middleware('auth:web')->get('/session-guarded', fn () => 'ok');

    $this->getJson('/session-guarded')
        ->assertUnauthorized()
        ->assertHeaderMissing('WWW-Authenticate')
        ->assertJson(['message' => 'Unauthenticated.']);
});
