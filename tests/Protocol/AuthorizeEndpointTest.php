<?php

declare(strict_types=1);

/**
 * OAuth 2.1 §4.1.1 / §4.1.2.1 (authorization request validation and error responses); RFC 8252 §7.3 (loopback redirects)
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function () {
    $this->withoutMiddleware([ValidateCsrfToken::class, PreventRequestForgery::class]);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->pkce = $this->pkce();
});

/**
 * @param  array<string, mixed>  $overrides
 * @return TestResponse<Response>
 */
function authorizeWith(mixed $test, array $overrides): TestResponse
{
    $query = array_filter(array_merge([
        'client_id' => $test->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid',
        'state' => 'st4te',
        'code_challenge' => $test->pkce->challenge,
        'code_challenge_method' => 'S256',
    ], $overrides), fn (mixed $value): bool => $value !== null);

    return $test->actingAsIdentity($test->user, authTime: time() - 60)
        ->get('/realms/default/oauth/authorize?'.http_build_query($query));
}

/**
 * @param  TestResponse<Response>  $response
 * @return array<string, string>
 */
function redirectParams(TestResponse $response): array
{
    $response->assertRedirect();
    expect($response->headers->get('Location'))->toStartWith('https://rp.test/callback?');
    parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $params);

    return $params;
}

it('rejects an unknown client without redirecting', function () {
    authorizeWith($this, ['client_id' => 'nope'])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

it('rejects a request without client_id', function () {
    authorizeWith($this, ['client_id' => null])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

it('falls back to the single registered redirect_uri when none is sent', function () {
    $view = authorizeWith($this, ['redirect_uri' => null])->assertOk();

    $approve = $this->post('/realms/default/oauth/authorize', ['auth_token' => $view->json('authToken')]);

    expect(redirectParams($approve))->toHaveKey('code');
});

it('requires redirect_uri when several are registered', function () {
    $this->client->forceFill(['redirect_uris' => ['https://rp.test/callback', 'https://rp.test/other']])->save();

    authorizeWith($this, ['redirect_uri' => null])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

// RFC 8252 §7.3
it('accepts a loopback redirect_uri on any port', function () {
    $this->client->forceFill(['redirect_uris' => ['http://127.0.0.1:8080/cb']])->save();

    authorizeWith($this, ['redirect_uri' => 'http://127.0.0.1:53211/cb'])->assertOk();
    authorizeWith($this, ['redirect_uri' => 'http://127.0.0.1:53211/other'])->assertStatus(400);
});

it('reports an unsupported response_type to the client', function () {
    $params = redirectParams(authorizeWith($this, ['response_type' => 'token']));

    expect($params['error'])->toBe('unsupported_response_type')
        ->and($params['state'])->toBe('st4te');
});

it('reports an unknown scope to the client', function () {
    $params = redirectParams(authorizeWith($this, ['scope' => 'openid nope']));

    expect($params['error'])->toBe('invalid_scope')
        ->and($params['state'])->toBe('st4te');
});

// OAuth 2.1 §4.1.1 — plain is gone
it('rejects the plain code_challenge_method', function () {
    $params = redirectParams(authorizeWith($this, ['code_challenge_method' => 'plain']));

    expect($params['error'])->toBe('invalid_request');
});

it('reports a client without the authorization_code grant to the client', function () {
    $this->client->forceFill(['grant_types' => ['client_credentials']])->save();

    expect(redirectParams(authorizeWith($this, []))['error'])->toBe('unauthorized_client');
});

// RFC 6749 §4.1.2.1 — denial
it('redirects a denied consent with access_denied and the state', function () {
    $view = authorizeWith($this, [])->assertOk();

    $params = redirectParams($this->delete('/realms/default/oauth/authorize', ['auth_token' => $view->json('authToken')]));

    expect($params['error'])->toBe('access_denied')
        ->and($params['state'])->toBe('st4te')
        ->and($params)->not->toHaveKey('code');
});

it('refuses to complete a consent with a foreign auth token', function () {
    authorizeWith($this, [])->assertOk();

    $this->post('/realms/default/oauth/authorize', ['auth_token' => 'forged'])->assertForbidden();
});
