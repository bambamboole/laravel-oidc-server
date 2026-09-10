<?php

declare(strict_types=1);

/**
 * OAuth 2.1 §4.3 refresh token grant, §4.3.1 (rotation, scope narrowing, chain revocation);
 * OpenID Connect Core 1.0 §12.2 (refreshed id_token); §8.3 session lifetime cap
 */

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AuthorizationCodeEvent;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function () {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

/**
 * Authorizes with the given login context and returns the refresh token of the first token response.
 *
 * @param  list<string>  $amr
 * @param  array<string, mixed>  $idTokenClaims
 * @param  array<string, mixed>  $accessTokenClaims
 */
function obtainRefreshToken(TestCase $test, array $amr = ['pwd'], array $idTokenClaims = [], array $accessTokenClaims = [], ?string $sid = null, string $scopes = 'openid email'): string
{
    $test->actingAsIdentity($test->user, idTokenClaims: $idTokenClaims, accessTokenClaims: $accessTokenClaims, amr: $amr, authTime: time() - 60);

    if ($sid !== null) {
        $test->withSession(['oidc.sid' => $sid]);
    }

    return (string) $test->authorizeAndApprove($test->user, $test->client, scopes: $scopes, params: ['nonce' => 'n0nce'])->refreshToken;
}

/**
 * @return TestResponse<Response>
 */
function refresh(TestCase $test, string $refreshToken, ?string $scope = null, mixed $client = null): TestResponse
{
    $client ??= $test->client;

    return $test->post('/realms/default/oauth/token', array_filter([
        'grant_type' => 'refresh_token',
        'client_id' => $client->id,
        'client_secret' => $client->plainSecret,
        'refresh_token' => $refreshToken,
        'scope' => $scope,
    ]));
}

it('reissues the login context claims on refresh without a fresh nonce', function () {
    $refreshToken = obtainRefreshToken($this, amr: ['pwd', 'otp'], idTokenClaims: ['groups' => ['admin']], accessTokenClaims: ['tier' => 'gold']);

    $response = refresh($this, $refreshToken)->assertOk();

    $idToken = parseIdToken($response->json('id_token'));
    $accessToken = parseAccessToken($response->json('access_token'));

    expect($idToken->claims()->has('nonce'))->toBeFalse()
        ->and($idToken->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and($idToken->claims()->get('acr'))->toBe('2')
        ->and($idToken->claims()->get('groups'))->toBe(['admin'])
        ->and($accessToken->claims()->get('tier'))->toBe('gold');
});

it('carries the sid claim and reruns the authorization-code trigger with the refresh grant type', function () {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);

    app(AccessTokenPipeline::class)->register('authorization_code', function (AuthorizationCodeEvent $event, AccessTokenApi $api): void {
        $api->setAccessTokenClaim('via', $event->grantType);
    });

    $response = refresh($this, obtainRefreshToken($this, sid: $sid))->assertOk();

    expect(parseIdToken($response->json('id_token'))->claims()->get('sid'))->toBe($sid)
        ->and(parseAccessToken($response->json('access_token'))->claims()->get('via'))->toBe('refresh_token');
});

it('rotates the refresh token and revokes the whole chain when a rotated-out token is reused', function () {
    $original = obtainRefreshToken($this);

    $rotated = refresh($this, $original)->assertOk();

    refresh($this, $original)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

    $current = parseAccessToken((string) $rotated->json('access_token'));

    expect(RefreshToken::query()->find($rotated->json('refresh_token'))->revoked)->toBeTrue()
        ->and(AccessToken::query()->find($current->claims()->get('jti'))->revoked)->toBeTrue();

    refresh($this, $rotated->json('refresh_token'))->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('narrows scopes on refresh and refuses escalation', function () {
    $narrowed = refresh($this, obtainRefreshToken($this), scope: 'openid')->assertOk();

    expect(parseAccessToken((string) $narrowed->json('access_token'))->claims()->get('scope'))->toBe('openid')
        ->and($narrowed->json('scope'))->toBe('openid');

    refresh($this, $narrowed->json('refresh_token'), scope: 'openid email')
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_scope');
});

it('rejects a refresh token presented by another client', function () {
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://o.test/cb']);

    refresh($this, obtainRefreshToken($this), client: $other)
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');
});

it('rejects an expired refresh token', function () {
    $refreshToken = obtainRefreshToken($this);
    RefreshToken::query()->whereKey($refreshToken)->update(['expires_at' => now()->subMinute()]);

    refresh($this, $refreshToken)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('denies refresh once the session absolute lifetime is exceeded', function () {
    $refreshToken = obtainRefreshToken($this);
    AuthenticationContext::query()->update(['expires_at' => now()->subMinute()]);

    refresh($this, $refreshToken)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('denies refresh after the session is revoked', function () {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $refreshToken = obtainRefreshToken($this, sid: $sid);

    app(OidcSessionRepository::class)->revoke($sid);

    refresh($this, $refreshToken)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});
