<?php

declare(strict_types=1);

/**
 * RFC 6750 §3 (bearer challenges from the auth:oidc guard); RFC 9068 §4 (typ, iss, aud); RFC 9728 §5.1 (resource_metadata)
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\Jwk;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\ClientPrincipal;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Workbench\App\Models\User;

const GUARD_RESOURCE_METADATA = 'resource_metadata="http://localhost/.well-known/oauth-protected-resource"';

beforeEach(function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    Route::middleware('auth:oidc')->get('/guarded', fn (): array => ['id' => auth()->id()]);
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
        ->issuedBy('https://other-issuer.test')
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

it('authenticates a token the realm issued and resolves the user from sub', function (): void {
    $jwt = resourceServerBearer($this);

    $this->getJson('/guarded', ['Authorization' => "Bearer $jwt"])
        ->assertOk()
        ->assertJson(['id' => $this->user->id]);
});

// RFC 9068 §4 — aud must name this resource; the issuing client is not an audience
it('accepts only tokens addressed to the issuer or a registered resource', function (): void {
    config(['oidc.resources' => ['https://api.example/orders' => []]]);

    $accepted = resourceServerBearer($this, ['https://api.example/orders']);
    $foreign = resourceServerBearer($this, ['https://other.example/api']);
    $issuerOnly = resourceServerBearer($this, [app(IssuerResolver::class)->url()]);
    $clientOnly = resourceServerBearer($this, [(string) $this->client->client_id]);

    $this->getJson('/guarded', ['Authorization' => "Bearer $accepted"])->assertOk();

    // The guard instance caches the user it resolved; drop it so each bearer is validated afresh.
    Auth::forgetGuards();
    $this->getJson('/guarded', ['Authorization' => "Bearer $foreign"])->assertUnauthorized();

    // The issuer stays an audience next to the registered resources.
    Auth::forgetGuards();
    $this->getJson('/guarded', ['Authorization' => "Bearer $issuerOnly"])->assertOk();

    Auth::forgetGuards();
    $this->getJson('/guarded', ['Authorization' => "Bearer $clientOnly"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token');
});

it('authenticates a userless token as the client it was issued to', function (): void {
    $machine = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    $jwt = clientCredentialsBearer($machine, ['orders.read']);

    Route::middleware('auth:oidc')->get('/machine', function (Request $request): array {
        $principal = $request->user();

        return [
            'principal' => $principal === null ? null : $principal::class,
            'id' => $principal?->getAuthIdentifier(),
            'scopes' => $principal?->currentAccessToken()?->scopes(),
        ];
    });

    $this->getJson('/machine', ['Authorization' => "Bearer $jwt"])
        ->assertOk()
        ->assertExactJson([
            'principal' => ClientPrincipal::class,
            'id' => $machine->client_id,
            'scopes' => ['orders.read'],
        ]);
});

it('rejects a userless token whose client is revoked or gone', function (string $case): void {
    $machine = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    $jwt = clientCredentialsBearer($machine);

    $case === 'revoked'
        ? $machine->forceFill(['revoked' => true])->save()
        : $machine->delete();

    $this->getJson('/guarded', ['Authorization' => "Bearer $jwt"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token');
})->with(['revoked', 'deleted']);

// RFC 6750 §3.1 — no credentials presented: a challenge without an error code
it('challenges a request without a bearer token and names no error', function (): void {
    $this->getJson('/guarded')
        ->assertUnauthorized()
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", '.GUARD_RESOURCE_METADATA)
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertNoContent(401);

    Route::get('/login', fn (): string => 'login')->name('login');
    Route::getRoutes()->refreshNameLookups();

    $this->get('/guarded')
        ->assertUnauthorized()
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", '.GUARD_RESOURCE_METADATA);
});

it('answers a rejected bearer token with invalid_token', function (string $case): void {
    $jwt = match ($case) {
        'garbage' => 'garbage',
        'revoked' => resourceServerBearer($this, revoked: true),
        'expired' => resourceServerBearer($this, expired: true),
        'foreign issuer' => bearerIssuedElsewhere($this),
        'unknown subject' => resourceServerBearer($this, subjectId: '999999'),
        'id_token as bearer' => persistedIdTokenAsBearer($this),
        'revoked machine token' => clientCredentialsBearer(app(ClientRepository::class)->createClientCredentialsGrantClient('M2M'), revoked: true),
        'machine token for another resource' => clientCredentialsBearer(app(ClientRepository::class)->createClientCredentialsGrantClient('M2M'), audience: ['https://other.example/api']),
        default => throw new LogicException('Unknown case.'),
    };

    $this->getJson('/guarded', ['Authorization' => "Bearer $jwt"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token')
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", error="invalid_token", '.GUARD_RESOURCE_METADATA);
})->with([
    'garbage',
    'revoked',
    'expired',
    'foreign issuer',
    'unknown subject',
    'id_token as bearer',
    'revoked machine token',
    'machine token for another resource',
]);

it('leaves other guards to Laravel', function (): void {
    Route::middleware('auth:web')->get('/session-guarded', fn (): string => 'ok');

    $this->getJson('/session-guarded')
        ->assertUnauthorized()
        ->assertHeaderMissing('WWW-Authenticate')
        ->assertJson(['message' => 'Unauthenticated.']);
});

it('challenges through the default guard when that guard is the oidc one', function (): void {
    config(['auth.defaults.guard' => 'oidc']);
    Route::middleware('auth')->get('/default-guarded', fn (): string => 'ok');

    $this->getJson('/default-guarded')
        ->assertUnauthorized()
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", '.GUARD_RESOURCE_METADATA);
});

it('leaves the default guard to Laravel when it is a session guard', function (): void {
    Route::middleware('auth')->get('/default-guarded', fn (): string => 'ok');

    $this->getJson('/default-guarded')
        ->assertUnauthorized()
        ->assertHeaderMissing('WWW-Authenticate')
        ->assertJson(['message' => 'Unauthenticated.']);
});
