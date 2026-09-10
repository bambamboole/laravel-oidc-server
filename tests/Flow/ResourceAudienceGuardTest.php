<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\Middleware\CheckScopes;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Workbench\App\Models\User;

beforeEach(function () {
    config(['oidc.scopes.catalog' => [
        'openid' => 'Authenticate',
    ]]);

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    $this->client->forceFill([
        'grant_types' => [...(array) $this->client->getAttribute('grant_types'), TestCase::TOKEN_EXCHANGE_GRANT],
        'allowed_exchange_audiences' => [app(IssuerResolver::class)->url(), 'https://other.example'],
    ])->save();

    Route::middleware('auth:oidc')->get('/probe', fn () => ['id' => auth()->id()]);
});

function exchangedTokenFor(object $context, string $audience): string
{
    $subject = mintExchangeSubjectToken((string) $context->client->getKey(), $context->user->getKey(), ['openid']);

    return $context->post('/realms/default/oauth/token', [
        'grant_type' => TestCase::TOKEN_EXCHANGE_GRANT,
        'client_id' => (string) $context->client->getKey(),
        'client_secret' => $context->client->plainSecret,
        'subject_token' => $subject,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        'audience' => $audience,
    ])->json('access_token');
}

it('authenticates an exchanged token addressed to the issuer', function () {
    $token = exchangedTokenFor($this, app(IssuerResolver::class)->url());

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
    $token = exchangedTokenFor($this, app(IssuerResolver::class)->url());

    $this->getJson('/probe', ['Authorization' => 'Bearer '.$token])->assertOk();

    $jti = parseAccessToken($token)->claims()->get('jti');
    AccessToken::query()->whereKey($jti)->update(['revoked' => true]);

    // The oidc guard caches the resolved user on itself after the first call, so a second
    // request in the same test would silently reuse it instead of re-validating; drop
    // the cached guard instance to force a fresh authentication.
    Auth::forgetGuards();

    $this->getJson('/probe', ['Authorization' => 'Bearer '.$token])->assertUnauthorized();
});

it('authenticates a PAT-shaped token identically to a classic authorization-code token', function () {
    $token = app(AccessTokenMinter::class)->mint(
        $this->user->getKey(),
        $this->client->client_id,
        ['openid'],
        new DateInterval('PT1H'),
    )->toString();

    $this->getJson('/probe', ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJson(['id' => $this->user->getKey()]);
});

it('passes the scope middleware placed after auth:oidc when the token has the scope', function () {
    Route::middleware(['auth:oidc', CheckScopes::using('openid')])
        ->get('/probe/scoped', fn () => ['id' => auth()->id()]);

    $token = exchangedTokenFor($this, app(IssuerResolver::class)->url());

    $this->getJson('/probe/scoped', ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJson(['id' => $this->user->getKey()]);
});

it('rejects the scope middleware placed after auth:oidc when the token lacks the scope', function () {
    Route::middleware(['auth:oidc', CheckScopes::using('admin')])
        ->get('/probe/scoped-missing', fn () => ['id' => auth()->id()]);

    $token = exchangedTokenFor($this, app(IssuerResolver::class)->url());

    $this->getJson('/probe/scoped-missing', ['Authorization' => 'Bearer '.$token])->assertForbidden();
});
