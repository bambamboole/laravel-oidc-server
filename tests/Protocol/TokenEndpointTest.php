<?php

declare(strict_types=1);

/**
 * RFC 6749 §3.2 / §5.2 (token endpoint, error responses); OAuth 2.1 §4.1.3 (code redemption), §4.3.1 (refresh rotation); RFC 7636 §4.6
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Bambamboole\LaravelOidc\Server\Testing\PkcePair;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function () {
    $this->withoutMiddleware([ValidateCsrfToken::class, PreventRequestForgery::class]);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

/**
 * Drives authorize + approve and returns the code from the redirect.
 *
 * @param  array<string, mixed>  $overrides
 */
function obtainAuthorizationCode(TestCase $test, PkcePair $pkce, array $overrides = []): string
{
    $view = $test->actingAsIdentity($test->user, authTime: time() - 60)
        ->get('/realms/default/oauth/authorize?'.http_build_query(array_merge([
            'client_id' => $test->client->id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid email',
            'state' => 'st4te',
            'code_challenge' => $pkce->challenge,
            'code_challenge_method' => 'S256',
        ], $overrides)))
        ->assertOk();

    $approve = $test->post('/realms/default/oauth/authorize', ['auth_token' => $view->json('authToken')])->assertRedirect();
    parse_str((string) parse_url((string) $approve->headers->get('Location'), PHP_URL_QUERY), $params);

    return $params['code'];
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function codeRedemption(TestCase $test, string $code, PkcePair $pkce, array $overrides = []): array
{
    return array_merge([
        'grant_type' => 'authorization_code',
        'client_id' => $test->client->id,
        'client_secret' => $test->client->plainSecret,
        'redirect_uri' => 'https://rp.test/callback',
        'code' => $code,
        'code_verifier' => $pkce->verifier,
    ], $overrides);
}

// RFC 6749 §5.2
it('rejects a token request without grant_type', function () {
    $this->post('/realms/default/oauth/token', [
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
});

it('rejects an unknown grant_type before authenticating the client', function () {
    $this->post('/realms/default/oauth/token', ['grant_type' => 'urn:example:nope'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'unsupported_grant_type');
});

// RFC 6749 §2.3.1 (client_secret_basic)
it('authenticates a client through HTTP Basic credentials', function () {
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    $response = $this->withBasicAuth($client->client_id, (string) $client->plainSecret)
        ->post('/realms/default/oauth/token', ['grant_type' => 'client_credentials'])
        ->assertOk();

    expect($response->json('token_type'))->toBe('Bearer')
        ->and($response->headers->get('Cache-Control'))->toContain('no-store')
        ->and($response->headers->get('Pragma'))->toBe('no-cache');
});

it('rejects a token request without client_id', function () {
    $this->post('/realms/default/oauth/token', ['grant_type' => 'client_credentials'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

it('rejects a wrong client secret with a Basic challenge', function () {
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->client_id,
        'client_secret' => 'wrong',
    ])->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client')
        ->assertHeader('WWW-Authenticate', 'Basic realm="OIDC"');
});

it('rejects a public client that presents a secret', function () {
    $public = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Public', ['https://p.test/cb'], confidential: false);

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $public->client_id,
        'client_secret' => 'unexpected',
        'refresh_token' => 'x',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

// RFC 6749 §5.2 (unauthorized_client)
it('rejects a client that is not registered for the grant', function () {
    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
    ])->assertStatus(400)->assertJsonPath('error', 'unauthorized_client');
});

// OAuth 2.1 §4.1.3 — a replayed code revokes everything it produced
it('revokes the tokens a replayed authorization code produced', function () {
    $pkce = $this->pkce();
    $code = obtainAuthorizationCode($this, $pkce);

    $first = $this->post('/realms/default/oauth/token', codeRedemption($this, $code, $pkce))->assertOk();

    $this->post('/realms/default/oauth/token', codeRedemption($this, $code, $pkce))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');

    $accessToken = parseAccessToken((string) $first->json('access_token'));

    expect(Token::query()->find($accessToken->claims()->get('jti'))->revoked)->toBeTrue()
        ->and(RefreshToken::query()->find($first->json('refresh_token'))->revoked)->toBeTrue();

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $first->json('refresh_token'),
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('rejects an expired authorization code', function () {
    $pkce = $this->pkce();
    $code = obtainAuthorizationCode($this, $pkce);
    AuthCode::query()->whereKey($code)->update(['expires_at' => now()->subMinute()]);

    $this->post('/realms/default/oauth/token', codeRedemption($this, $code, $pkce))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');
});

it('rejects a code issued to another client', function () {
    $pkce = $this->pkce();
    $code = obtainAuthorizationCode($this, $pkce);
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://rp.test/callback']);

    $this->post('/realms/default/oauth/token', codeRedemption($this, $code, $pkce, [
        'client_id' => $other->id,
        'client_secret' => $other->plainSecret,
    ]))->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

    // The code survives a foreign redemption attempt for its rightful client.
    $this->post('/realms/default/oauth/token', codeRedemption($this, $code, $pkce))->assertOk();
});

// RFC 6749 §4.1.3 — redirect_uri must be repeated and must match
it('requires the redirect_uri the authorization request carried', function () {
    $pkce = $this->pkce();
    $code = obtainAuthorizationCode($this, $pkce);

    $this->post('/realms/default/oauth/token', codeRedemption($this, $code, $pkce, ['redirect_uri' => null]))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');

    $this->post('/realms/default/oauth/token', codeRedemption($this, $code, $pkce, ['redirect_uri' => 'https://rp.test/other']))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');
});

// RFC 7636 §4.6
it('requires a well-formed code_verifier', function () {
    $pkce = $this->pkce();
    $code = obtainAuthorizationCode($this, $pkce);

    $this->post('/realms/default/oauth/token', codeRedemption($this, $code, $pkce, ['code_verifier' => null]))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');

    $this->post('/realms/default/oauth/token', codeRedemption($this, $code, $pkce, ['code_verifier' => 'too-short']))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');

    $this->post('/realms/default/oauth/token', codeRedemption($this, $code, $pkce, ['code_verifier' => str_repeat('x', 64)]))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');
});

it('issues no refresh token to a client without the refresh_token grant', function () {
    $this->client->forceFill(['grant_types' => ['authorization_code']])->save();

    $result = $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid');

    $result->response->assertOk()->assertJsonMissingPath('refresh_token');
});

// OAuth 2.1 §4.3.1 — refreshed scopes may only narrow
it('narrows scopes on refresh and refuses escalation', function () {
    $result = $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid email');

    $narrowed = $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $result->refreshToken,
        'scope' => 'openid',
    ])->assertOk();

    expect(parseAccessToken((string) $narrowed->json('access_token'))->claims()->get('scope'))->toBe('openid');

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $narrowed->json('refresh_token'),
        'scope' => 'openid email',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_scope');
});

it('rejects a refresh token presented by another client', function () {
    $result = $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid');
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://o.test/cb']);

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $other->id,
        'client_secret' => $other->plainSecret,
        'refresh_token' => $result->refreshToken,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('rejects an expired refresh token', function () {
    $result = $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid');
    RefreshToken::query()->whereKey($result->refreshToken)->update(['expires_at' => now()->subMinute()]);

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $result->refreshToken,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

// OAuth 2.1 §4.3.1 — reuse of a rotated-out refresh token revokes the chain
it('revokes the whole chain when a rotated-out refresh token is reused', function () {
    $result = $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid');

    $rotated = $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $result->refreshToken,
    ])->assertOk();

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $result->refreshToken,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

    $current = parseAccessToken((string) $rotated->json('access_token'));

    expect(RefreshToken::query()->find($rotated->json('refresh_token'))->revoked)->toBeTrue()
        ->and(Token::query()->find($current->claims()->get('jti'))->revoked)->toBeTrue();
});
