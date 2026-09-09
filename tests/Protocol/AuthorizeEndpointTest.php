<?php

declare(strict_types=1);

/**
 * OAuth 2.1 §4.1.1 / §4.1.2.1 (authorization request validation and error responses); RFC 8252 §7.3 (loopback redirects);
 * OpenID Connect Core §3.1.2.1 (GET and POST, prompt, max_age, id_token_hint), §3.1.2.6 (error codes); RFC 9207 §2 (iss);
 * OAuth 2.0 Multiple Response Type Encoding Practices §2.1 (response_mode)
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
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
 * @return array<string, mixed>
 */
function authorizeParameters(mixed $test, array $overrides): array
{
    return array_filter(array_merge([
        'client_id' => $test->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid',
        'state' => 'st4te',
        'code_challenge' => $test->pkce->challenge,
        'code_challenge_method' => 'S256',
    ], $overrides), fn (mixed $value): bool => $value !== null);
}

/**
 * @param  array<string, mixed>  $overrides
 * @return TestResponse<Response>
 */
function authorizeWith(mixed $test, array $overrides): TestResponse
{
    return $test->actingAsIdentity($test->user, authTime: time() - 60)
        ->get('/realms/default/oauth/authorize?'.http_build_query(authorizeParameters($test, $overrides)));
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

// RFC 6749 §4.1.2.1: the resource owner is informed, never redirected, and no client authentication is challenged.
it('rejects an unknown client without redirecting', function () {
    authorizeWith($this, ['client_id' => 'nope'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request')
        ->assertHeaderMissing('WWW-Authenticate');
});

it('rejects a request without client_id', function () {
    authorizeWith($this, ['client_id' => null])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request')
        ->assertHeaderMissing('WWW-Authenticate');
});

it('falls back to the single registered redirect_uri when none is sent', function () {
    $view = authorizeWith($this, ['redirect_uri' => null])->assertOk();

    $approve = $this->post('/realms/default/oauth/authorize/consent', ['auth_token' => $view->json('authToken')]);

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

    $params = redirectParams($this->delete('/realms/default/oauth/authorize/consent', ['auth_token' => $view->json('authToken')]));

    expect($params['error'])->toBe('access_denied')
        ->and($params['state'])->toBe('st4te')
        ->and($params)->not->toHaveKey('code');
});

it('refuses to complete a consent with a foreign auth token', function () {
    authorizeWith($this, [])->assertOk();

    $this->post('/realms/default/oauth/authorize/consent', ['auth_token' => 'forged'])->assertForbidden();
});

// OIDC Core §3.1.2.1 — GET and POST
it('accepts the authorization request as a POST with form-encoded parameters', function () {
    $view = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->post('/realms/default/oauth/authorize', authorizeParameters($this, []))
        ->assertOk();

    expect(redirectParams($this->post('/realms/default/oauth/authorize/consent', ['auth_token' => $view->json('authToken')])))->toHaveKey('code');
});

it('reads a POST authorization request from the body only, never from the query', function () {
    $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->post('/realms/default/oauth/authorize?'.http_build_query(authorizeParameters($this, [])), ['scope' => 'openid'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

// OIDC Core §3.1.2.1 / §3.1.2.6 — max_age with prompt=none
it('answers login_required for prompt=none with an expired max_age and keeps the session', function () {
    $params = redirectParams(authorizeWith($this, ['prompt' => 'none', 'max_age' => '10']));

    expect($params['error'])->toBe('login_required')
        ->and($params['state'])->toBe('st4te')
        ->and(auth('identity')->check())->toBeTrue();
});

it('rejects a malformed max_age on the redirect URI', function () {
    expect(redirectParams(authorizeWith($this, ['max_age' => '-1']))['error'])->toBe('invalid_request');
});

// OIDC Core §3.1.2.1 — prompt
it('rejects prompt=none combined with another value', function () {
    $params = redirectParams(authorizeWith($this, ['prompt' => 'none login']));

    expect($params['error'])->toBe('invalid_request')
        ->and($params['state'])->toBe('st4te')
        ->and(auth('identity')->check())->toBeTrue();
});

it('rejects an unknown prompt value', function () {
    expect(redirectParams(authorizeWith($this, ['prompt' => 'wizard']))['error'])->toBe('invalid_request');
});

it('forces re-authentication for prompt=login', function () {
    config(['oidc.login_route' => 'identity.login']);

    authorizeWith($this, ['prompt' => 'login'])->assertRedirect(route('identity.login'));

    expect(auth('identity')->guest())->toBeTrue()
        ->and(session('promptedForLogin'))->toBeTrue();
});

it('treats prompt=select_account like prompt=login', function () {
    config(['oidc.login_route' => 'identity.login']);

    authorizeWith($this, ['prompt' => 'select_account'])->assertRedirect(route('identity.login'));

    expect(auth('identity')->guest())->toBeTrue()
        ->and(session('promptedForLogin'))->toBeTrue();
});

// OAuth 2.0 Multiple Response Type Encoding Practices §2.1
it('rejects a response_mode other than query', function () {
    $params = redirectParams(authorizeWith($this, ['response_mode' => 'fragment']));

    expect($params['error'])->toBe('invalid_request')
        ->and($params['state'])->toBe('st4te');
});

it('accepts response_mode=query', function () {
    authorizeWith($this, ['response_mode' => 'query'])->assertOk();
});

// OIDC Core §3.1.2.6 / §6 — request objects are not supported
it('answers request_not_supported for a request parameter', function () {
    $params = redirectParams(authorizeWith($this, ['request' => 'eyJhbGciOiJub25lIn0.e30.']));

    expect($params['error'])->toBe('request_not_supported')
        ->and($params['state'])->toBe('st4te');
});

it('answers request_uri_not_supported for a request_uri parameter', function () {
    $params = redirectParams(authorizeWith($this, ['request_uri' => 'https://rp.test/request.jwt']));

    expect($params['error'])->toBe('request_uri_not_supported')
        ->and($params['state'])->toBe('st4te');
});

// OIDC Core §3.1.2.1 — id_token_hint
it('answers login_required when the id_token_hint names another user', function () {
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $hint = $this->authorizeAndApprove($other, $this->client)->idToken;

    $params = redirectParams(authorizeWith($this, ['id_token_hint' => $hint]));

    expect($params['error'])->toBe('login_required')
        ->and($params['state'])->toBe('st4te')
        ->and(auth('identity')->check())->toBeTrue();
});

it('proceeds when the id_token_hint names the current user', function () {
    $hint = $this->authorizeAndApprove($this->user, $this->client)->idToken;

    // The approval above granted openid, so consent is skipped and a code is issued.
    expect(redirectParams(authorizeWith($this, ['id_token_hint' => $hint])))->toHaveKey('code');
});

it('rejects an unverifiable id_token_hint on the redirect URI', function () {
    $params = redirectParams(authorizeWith($this, ['id_token_hint' => 'not.a.jwt']));

    expect($params['error'])->toBe('invalid_request')
        ->and($params['state'])->toBe('st4te');
});

// OAuth 2.1 §4.1.1 / RFC 6749 §3.1 — duplicate parameters
it('rejects a duplicated scope parameter on the redirect URI', function () {
    $params = redirectParams($this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get('/realms/default/oauth/authorize?'.http_build_query(authorizeParameters($this, [])).'&scope=openid'));

    expect($params['error'])->toBe('invalid_request')
        ->and($params['state'])->toBe('st4te');
});

it('rejects a duplicated client_id parameter without redirecting', function () {
    $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get('/realms/default/oauth/authorize?'.http_build_query(authorizeParameters($this, [])).'&client_id='.$this->client->id)
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

it('rejects a duplicated parameter in a POST body', function () {
    $parameters = authorizeParameters($this, []);
    $body = http_build_query($parameters).'&state=other';

    $params = redirectParams($this->actingAsIdentity($this->user, authTime: time() - 60)
        ->call('POST', '/realms/default/oauth/authorize', $parameters, [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], $body));

    expect($params['error'])->toBe('invalid_request');
});

// RFC 9207 §2
it('adds iss to the code redirect', function () {
    $view = authorizeWith($this, [])->assertOk();

    $params = redirectParams($this->post('/realms/default/oauth/authorize/consent', ['auth_token' => $view->json('authToken')]));

    expect($params)->toHaveKey('code')
        ->and($params['iss'])->toBe(app(IssuerResolver::class)->url());
});

it('adds iss to error redirects', function () {
    $params = redirectParams(authorizeWith($this, ['response_type' => 'token']));

    expect($params['error'])->toBe('unsupported_response_type')
        ->and($params['iss'])->toBe(app(IssuerResolver::class)->url());
});
