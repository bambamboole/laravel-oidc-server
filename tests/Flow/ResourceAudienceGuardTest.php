<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Issuer;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Workbench\App\Models\User;

beforeEach(function () {
    Passport::tokensCan([
        'openid' => 'Authenticate',
    ]);

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    $this->client->forceFill([
        'grant_types' => [...(array) $this->client->getAttribute('grant_types'), TestCase::TOKEN_EXCHANGE_GRANT],
        'allowed_exchange_audiences' => json_encode([Issuer::url(), 'https://other.example']),
    ])->save();

    Route::middleware('auth:api')->get('/probe', fn () => ['id' => auth()->id()]);
});

function exchangedTokenFor(object $context, string $audience): string
{
    $subject = mintExchangeSubjectToken((string) $context->client->getKey(), $context->user->getKey(), ['openid']);

    return $context->post('/oauth/token', [
        'grant_type' => TestCase::TOKEN_EXCHANGE_GRANT,
        'client_id' => (string) $context->client->getKey(),
        'client_secret' => $context->client->plainSecret,
        'subject_token' => $subject,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        'audience' => $audience,
    ])->json('access_token');
}

it('authenticates an exchanged token addressed to the issuer', function () {
    $token = exchangedTokenFor($this, Issuer::url());

    $this->getJson('/probe', ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJson(['id' => $this->user->getKey()]);
});

it('rejects an exchanged token addressed to a foreign audience', function () {
    $token = exchangedTokenFor($this, 'https://other.example');

    $this->getJson('/probe', ['Authorization' => 'Bearer '.$token])->assertUnauthorized();
});

it('authenticates a foreign audience listed in resource audiences', function () {
    config()->set('oidc.resource.audiences', ['https://other.example']);

    $token = exchangedTokenFor($this, 'https://other.example');

    $this->getJson('/probe', ['Authorization' => 'Bearer '.$token])->assertOk();
});

it('still authenticates a classic token whose aud is the client id', function () {
    $token = mintExchangeSubjectToken((string) $this->client->getKey(), $this->user->getKey(), ['openid']);

    $this->getJson('/probe', ['Authorization' => 'Bearer '.$token])->assertOk();
});

it('rejects a revoked exchanged token', function () {
    $token = exchangedTokenFor($this, Issuer::url());

    $this->getJson('/probe', ['Authorization' => 'Bearer '.$token])->assertOk();

    $jti = parseAccessToken($token)->claims()->get('jti');
    Passport::token()->newQuery()->whereKey($jti)->update(['revoked' => true]);

    // TokenGuard caches the resolved user on itself after the first call, so a second
    // request in the same test would silently reuse it instead of re-validating; drop
    // the cached guard instance to force a fresh ResourceServer round trip.
    Auth::forgetGuards();

    $this->getJson('/probe', ['Authorization' => 'Bearer '.$token])->assertUnauthorized();
});
