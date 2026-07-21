<?php

declare(strict_types=1);

/**
 * OpenID Connect RP-Initiated Logout 1.0 §2 (id_token_hint, post_logout_redirect_uri, state), §4 (security/CSRF)
 */

use Bambamboole\LaravelOidc\Tests\TestCase;
use Bambamboole\LaravelOidc\Token\IdTokenBuilder;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\Bridge\Client as BridgeClient;
use Laravel\Passport\Bridge\Scope as BridgeScope;
use Laravel\Passport\ClientRepository;
use League\OAuth2\Server\CryptKey;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->client->forceFill(['post_logout_redirect_uris' => json_encode(['https://rp.test/logged-out'])])->save();
});

function issueIdToken(TestCase $test, ?User $subject = null): string
{
    $user = $subject ?? $test->user;
    $client = new BridgeClient((string) $test->client->id, 'RP', ['https://rp.test/callback']);
    $token = new AccessToken((string) $user->id, [new BridgeScope('openid')], $client);
    $token->setIdentifier('tid');
    $token->setExpiryDateTime(new DateTimeImmutable('+1 hour'));
    $token->setPrivateKey(new CryptKey(__DIR__.'/../fixtures/oauth-private.key', null, false));

    return app(IdTokenBuilder::class)->build($token, null, null);
}

it('logs out and redirects to a registered post_logout_redirect_uri', function () {
    $response = $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        'state' => 'xyz',
    ]));

    $response->assertRedirect('https://rp.test/logged-out?state=xyz');
    expect(auth('identity')->guest())->toBeTrue();
});

it('preserves an existing query string when appending state', function () {
    $this->client->forceFill([
        'post_logout_redirect_uris' => json_encode(['https://rp.test/logged-out?tenant=abc']),
    ])->save();

    $response = $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'post_logout_redirect_uri' => 'https://rp.test/logged-out?tenant=abc',
        'state' => 'xyz',
    ]));

    $response->assertRedirect('https://rp.test/logged-out?tenant=abc&state=xyz');
    expect(auth('identity')->guest())->toBeTrue();
});

it('falls back to the configured redirect for unregistered uris', function () {
    $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'post_logout_redirect_uri' => 'https://evil.test/phish',
    ]))->assertRedirect('/');
});

it('does not log out on a GET without a valid id_token_hint', function () {
    $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => 'garbage',
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
    ]))->assertRedirect('/');

    expect(auth('identity')->check())->toBeTrue();
});

it('does not log out on a parameterless GET', function () {
    $this->actingAs($this->user, 'identity')->get('/oauth/logout')->assertRedirect('/');

    expect(auth('identity')->check())->toBeTrue();
});

it('logs out on a POST without a valid id_token_hint', function () {
    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->actingAs($this->user, 'identity')
        ->post('/oauth/logout')
        ->assertRedirect('/');

    expect(auth('identity')->guest())->toBeTrue();
});

it('logs out on a GET with a valid id_token_hint', function () {
    $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
    ]))->assertRedirect('/');

    expect(auth('identity')->guest())->toBeTrue();
});

it('does not log out when the hint sub does not match the current user', function () {
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'x']);

    $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this, $other),
    ]))->assertRedirect('/');

    expect(auth('identity')->check())->toBeTrue();
});
