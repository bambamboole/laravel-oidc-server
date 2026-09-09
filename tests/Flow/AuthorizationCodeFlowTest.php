<?php
declare(strict_types=1);

/**
 * OAuth 2.1 §4.1 authorization code grant + RFC 7636 PKCE (S256); OpenID Connect Core 1.0 §3.1.3 (id_token issuance/validation)
 */

use Bambamboole\LaravelOidc\Server\Authentication\Context\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Consents\Controllers\ApproveAuthorizationController;
use Bambamboole\LaravelOidc\Server\Consents\Controllers\DenyAuthorizationController;
use Bambamboole\LaravelOidc\Server\Protocol\Controllers\AuthorizationController;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\Context\AccessTokenContext;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AuthorizationCodeEvent;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Testing\TestResponse;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function () {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    fakeConsentViewUsing(fn (array $parameters) => response()->json([
        'authToken' => $parameters['authToken'],
        'scopes' => $parameters['scopes'],
    ]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

/**
 * @param  array<string, mixed>  $overrides
 * @param  array<string, mixed>  $session
 * @return TestResponse<JsonResponse>
 */
function completeAuthorizationCodeFlow(TestCase $test, array $overrides = [], array $session = []): TestResponse
{
    $test->actingAsIdentity(
        $test->user,
        amr: $session[AuthSessionState::AMR_KEY] ?? [],
        authTime: $session['oidc.auth_time'] ?? time() - 60,
    );

    $extra = array_diff_key($session, array_flip(['oidc.auth_time', AuthSessionState::AMR_KEY]));

    if ($extra !== []) {
        $test->withSession($extra);
    }

    $params = array_merge(['state' => 'st4te', 'nonce' => 'n0nce'], $overrides);

    return $test->authorizeAndApprove($test->user, $test->client, scopes: 'openid email', params: $params)->response;
}

// OIDC Core §3.1.3.6 (at_hash)
it('issues an id_token through the full code + pkce flow', function () {
    config(['app.url' => 'https://op.test', 'oidc.issuer' => null]);

    $response = completeAuthorizationCodeFlow($this)->assertOk();

    expect($response->json())->toHaveKeys(['access_token', 'refresh_token', 'id_token']);

    $idToken = parseIdToken($response->json('id_token'));

    expect($idToken->claims()->get('iss'))->toBe('https://op.test/realms/default')
        ->and($idToken->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($idToken->claims()->get('aud'))->toBe([$this->client->id])
        ->and($idToken->claims()->get('nonce'))->toBe('n0nce')
        ->and($idToken->claims()->get('auth_time'))->toBeInt()
        ->and($idToken->claims()->get('email'))->toBe('m@example.com');

    $expectedAtHash = rtrim(strtr(base64_encode(
        substr(hash('sha256', $response->json('access_token'), true), 0, 16)
    ), '+/', '-_'), '=');
    expect($idToken->claims()->get('at_hash'))->toBe($expectedAtHash);

    expect((new Validator)->validate($idToken, new SignedWith(
        new Sha256, InMemory::plainText(signingPublicKey()),
    )))->toBeTrue();

    $jwks = $this->getJson('/realms/default/.well-known/jwks.json')->json('keys');
    expect($idToken->headers()->get('kid'))->toBe($jwks[0]['kid']);
});

it('merges authorization-code trigger claims into issued and refreshed access tokens', function () {
    app(AccessTokenPipeline::class)->register('authorization_code', function (AuthorizationCodeEvent $event, AccessTokenApi $api): void {
        expect($event->user->getAuthIdentifier())->toBe($this->user->id)
            ->and((string) $event->client->getKey())->toBe((string) $this->client->id)
            ->and($event->scopes)->toBe(['openid', 'email']);

        $api->setAccessTokenClaim('project_id', 'p-1');
        $api->setAccessTokenClaim('via', $event->grantType);
    });

    $response = completeAuthorizationCodeFlow($this)->assertOk();
    $accessToken = parseAccessToken((string) $response->json('access_token'));

    expect($accessToken->claims()->get('project_id'))->toBe('p-1')
        ->and($accessToken->claims()->get('via'))->toBe('authorization_code');

    $refreshed = $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $response->json('refresh_token'),
    ])->assertOk();

    $refreshedToken = parseAccessToken((string) $refreshed->json('access_token'));

    expect($refreshedToken->claims()->get('project_id'))->toBe('p-1')
        ->and($refreshedToken->claims()->get('via'))->toBe('refresh_token');
});

it('denies authorization-code issuance before persisting when a trigger denies', function () {
    $persistedTokenCount = Token::query()->count();

    app(AccessTokenPipeline::class)->register('authorization_code', function (AuthorizationCodeEvent $event, AccessTokenApi $api): void {
        $api->deny('user_blocked');
    });

    completeAuthorizationCodeFlow($this)
        ->assertStatus(400)
        ->assertJsonPath('error', 'access_denied')
        ->assertJsonMissingPath('access_token');

    expect(Token::query()->count())->toBe($persistedTokenCount);
});

// OIDC Core §3.1.2.1 / §5.4 (openid scope)
it('omits the id_token without the openid scope', function () {
    $response = completeAuthorizationCodeFlow($this, ['scope' => 'email'])->assertOk();

    expect($response->json())->toHaveKey('access_token')
        ->and($response->json())->not->toHaveKey('id_token');
});

// OAuth 2.1 §4.3 (refresh) + OIDC Core §12.2 — refresh REISSUES the persisted context
it('reissues amr/acr and claims on refresh, without a fresh nonce', function () {
    $refreshToken = completeAuthorizationCodeFlow($this, [], [
        'oidc.amr' => ['pwd', 'otp'],
        'oidc.id_token_claims' => ['groups' => ['admin']],
        'oidc.access_token_claims' => ['tier' => 'gold'],
    ])->json('refresh_token');

    $response = $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $refreshToken,
    ])->assertOk();

    $idToken = parseIdToken($response->json('id_token'));
    $accessToken = parseIdToken($response->json('access_token'));

    expect($idToken->claims()->has('nonce'))->toBeFalse()
        ->and($idToken->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and($idToken->claims()->get('acr'))->toBe('2')
        ->and($idToken->claims()->get('groups'))->toBe(['admin'])
        ->and($accessToken->claims()->get('tier'))->toBe('gold');
});

it('denies refresh once the context is gone', function () {
    $refreshToken = completeAuthorizationCodeFlow($this, [], ['oidc.amr' => ['pwd']])->json('refresh_token');

    AuthenticationContext::query()->delete();

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $refreshToken,
    ])->assertStatus(400);
});

it('denies refresh once the session absolute lifetime is exceeded', function () {
    $refreshToken = completeAuthorizationCodeFlow($this, [], ['oidc.amr' => ['pwd']])->json('refresh_token');

    AuthenticationContext::query()->update(['expires_at' => now()->subMinute()]);

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $refreshToken,
    ])->assertStatus(400);
});

it('does not leak a denied refresh context into the next refresh on the same grant instance', function () {
    // Octane-safety: a denied refresh must leave nothing behind for the next one. Deny
    // one refresh, then reissue a different one and assert its claims are its own.
    $deniedRefreshToken = completeAuthorizationCodeFlow($this, [], ['oidc.amr' => ['pwd']])->json('refresh_token');

    AuthenticationContext::query()->delete();

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $deniedRefreshToken,
    ])->assertStatus(400);

    // A different user avoids the "already granted these scopes" consent skip,
    // which would otherwise short-circuit completeAuthorizationCodeFlow() with a redirect.
    $this->user = User::create(['name' => 'N', 'email' => 'n@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    $validRefreshToken = completeAuthorizationCodeFlow($this, [], [
        'oidc.amr' => ['pwd', 'otp'],
        'oidc.id_token_claims' => ['groups' => ['ops']],
    ])->json('refresh_token');

    $response = $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $validRefreshToken,
    ])->assertOk();

    $idToken = parseIdToken($response->json('id_token'));

    expect($idToken->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and($idToken->claims()->get('groups'))->toBe(['ops']);
});

// OIDC Core §3.1.3.6 / RFC 8176 (amr) + §2 (acr derived from amr method count)
it('carries amr from the session into the auth_code id_token with derived acr', function () {
    $response = completeAuthorizationCodeFlow($this, [], ['oidc.amr' => ['pwd', 'otp']])->assertOk();

    $idToken = parseIdToken($response->json('id_token'));
    expect($idToken->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and($idToken->claims()->get('acr'))->toBe('2');
});

it('emits acr "1" for a single-method session', function () {
    $response = completeAuthorizationCodeFlow($this, [], ['oidc.amr' => ['pwd']])->assertOk();

    $idToken = parseIdToken($response->json('id_token'));
    expect($idToken->claims()->get('amr'))->toBe(['pwd'])
        ->and($idToken->claims()->get('acr'))->toBe('1');
});

it('omits amr and acr when the session held no methods', function () {
    $idToken = parseIdToken(completeAuthorizationCodeFlow($this)->assertOk()->json('id_token'));

    expect($idToken->claims()->has('amr'))->toBeFalse()
        ->and($idToken->claims()->has('acr'))->toBeFalse();
});

// OAuth 2.1 §4.1.1 / §7.6 (PKCE required for every client)
it('rejects an authorization request without PKCE even for a confidential client', function () {
    $response = $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/authorize?'.http_build_query([
        'client_id' => $this->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid',
        'state' => 'st4te',
    ]));

    // RFC 7636 §4.4.1: the client and redirect_uri are valid, so the error
    // travels back to the client as an authorization error response.
    $response->assertRedirect();
    parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $params);

    expect($response->headers->get('Location'))->toStartWith('https://rp.test/callback?')
        ->and($params['error'])->toBe('invalid_request')
        ->and($params['state'])->toBe('st4te');
});

it('emits postLogin-buffered id_token claims via the context store', function () {
    $response = completeAuthorizationCodeFlow($this, [], [
        'oidc.amr' => ['pwd', 'otp'],
        'oidc.id_token_claims' => ['groups' => ['admin']],
    ])->assertOk();

    $idToken = parseIdToken($response->json('id_token'));
    expect($idToken->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and($idToken->claims()->get('acr'))->toBe('2')
        ->and($idToken->claims()->get('groups'))->toBe(['admin']);
});

// §8.3 — every interactive session is capped
it('always persists a context row with a future expires_at', function () {
    completeAuthorizationCodeFlow($this, [], [
        'oidc.amr' => ['pwd'],
        'oidc.access_token_claims' => ['tier' => 'gold'],
    ])->assertOk();

    $context = AuthenticationContext::query()->sole();
    expect($context->user_id)->toBe((string) $this->user->id)
        ->and($context->amr)->toBe(['pwd'])
        ->and($context->access_token_claims)->toBe(['tier' => 'gold'])
        ->and($context->expires_at->isFuture())->toBeTrue();
});

// §5/§7 — access-token custom claims on fresh issuance
it('emits postLogin access-token claims onto the access token and links it', function () {
    $response = completeAuthorizationCodeFlow($this, [], [
        'oidc.amr' => ['pwd'],
        'oidc.access_token_claims' => ['tier' => 'gold', 'amr' => ['hax']],
    ])->assertOk();

    $accessToken = parseIdToken($response->json('access_token')); // parses any JWT
    expect($accessToken->claims()->get('tier'))->toBe('gold')
        ->and($accessToken->claims()->has('amr'))->toBeFalse(); // reserved name skipped

    // the issued access token is linked to a context
    expect(AccessTokenContext::query()->count())->toBe(1);
});

// Octane safety: state left behind by a *failed* token exchange must never leak
// into a later token request handled by the same worker.
it('does not leak state from a failed token request into a later one', function () {
    // First flow: seed a distinguishing access-token claim, then fail the token
    // exchange with a wrong code_verifier so the PKCE check rejects it before
    // anything is issued.
    $pkce1 = $this->pkce();

    $view1 = $this->actingAsIdentity($this->user, accessTokenClaims: ['leaked' => true], authTime: time() - 60)
        ->get('/realms/default/oauth/authorize?'.http_build_query([
            'client_id' => $this->client->id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid email',
            'state' => 'st4te',
            'nonce' => 'n0nce',
            'code_challenge' => $pkce1->challenge,
            'code_challenge_method' => 'S256',
        ]))
        ->assertOk();

    $approve1 = $this->post('/realms/default/oauth/authorize/consent', ['auth_token' => $view1->json('authToken')])
        ->assertRedirect();
    parse_str(parse_url($approve1->headers->get('Location'), PHP_URL_QUERY), $params1);

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'redirect_uri' => 'https://rp.test/callback',
        'code' => $params1['code'],
        'code_verifier' => str_repeat('x', 64), // wrong verifier -> PKCE failure
    ])->assertStatus(400);

    // Second, clean flow: no access_token_claims in session at all.
    $pkce2 = $this->pkce();

    $view2 = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get('/realms/default/oauth/authorize?'.http_build_query([
            'client_id' => $this->client->id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid email',
            'state' => 'st4te',
            'nonce' => 'n0nce2',
            'code_challenge' => $pkce2->challenge,
            'code_challenge_method' => 'S256',
        ]))
        ->assertOk();

    $approve2 = $this->post('/realms/default/oauth/authorize/consent', ['auth_token' => $view2->json('authToken')])
        ->assertRedirect();
    parse_str(parse_url($approve2->headers->get('Location'), PHP_URL_QUERY), $params2);

    // Force this request's own context lookup to miss, so nothing but leaked
    // state could put the first flow's claim onto this token.
    AuthenticationContext::query()->delete();

    $response = $this->post('/realms/default/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'redirect_uri' => 'https://rp.test/callback',
        'code' => $params2['code'],
        'code_verifier' => $pkce2->verifier,
    ])->assertOk();

    $accessToken = parseIdToken($response->json('access_token'));
    expect($accessToken->claims()->has('leaked'))->toBeFalse();
});

// Inertia XHR can't navigate the browser to the client's redirect_uri (e.g. a
// custom-scheme mobile callback), so approve/deny must hand it the 409 +
// X-Inertia-Location protocol instead of a plain redirect it would swallow.
it('answers an Inertia approve request with a 409 + X-Inertia-Location instead of a redirect', function () {
    $pkce = $this->pkce();

    $view = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get('/realms/default/oauth/authorize?'.http_build_query([
            'client_id' => $this->client->id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'st4te',
            'code_challenge' => $pkce->challenge,
            'code_challenge_method' => 'S256',
        ]))
        ->assertOk();

    $approve = $this->post(route('oidc.approve'), [
        'auth_token' => $view->json('authToken'),
    ], ['X-Inertia' => 'true']);

    $approve->assertStatus(409);
    expect($approve->headers->get('X-Inertia-Location'))->toStartWith('https://rp.test/callback?');
});

// A trusted client skips consent entirely (hasGrantedScopes()), so the
// redirect_uri redirect is issued straight from authorize() rather than
// approve() — it needs the same Inertia-safety net as the approve/deny
// controllers, or the redirect is silently swallowed client-side.
it('answers a trusted client\'s Inertia authorize request with a 409 + X-Inertia-Location instead of a redirect', function () {
    config()->set('oidc.trusted_clients', [(string) $this->client->getKey()]);
    $pkce = $this->pkce();

    $response = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get('/realms/default/oauth/authorize?'.http_build_query([
            'client_id' => $this->client->id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'st4te',
            'code_challenge' => $pkce->challenge,
            'code_challenge_method' => 'S256',
        ]), ['X-Inertia' => 'true']);

    $response->assertStatus(409);
    expect($response->headers->get('X-Inertia-Location'))->toStartWith('https://rp.test/callback?');
});

/**
 * The authorize route runs on bare `web` middleware — no `auth` guard — so the
 * guest redirect is the controller's own `promptForLogin()`, sending the visitor
 * to `oidc.login_route` and flagging the session so a later `max_age` check does
 * not force a second round trip.
 */
it('redirects a guest authorize request to the configured login route', function () {
    config(['oidc.login_route' => 'identity.login']);
    $pkce = $this->pkce();

    $this->get('/realms/default/oauth/authorize?'.http_build_query([
        'client_id' => $this->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid',
        'state' => 'st4te',
        'code_challenge' => $pkce->challenge,
        'code_challenge_method' => 'S256',
    ]))->assertRedirect(route('identity.login'));

    expect(session('promptedForLogin'))->toBeTrue();
});

it('redirects a guest to a plain path when login_route is not a registered route name', function () {
    config(['oidc.login_route' => 'accounts/sign-in']);
    $pkce = $this->pkce();

    $this->get('/realms/default/oauth/authorize?'.http_build_query([
        'client_id' => $this->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid',
        'state' => 'st4te',
        'code_challenge' => $pkce->challenge,
        'code_challenge_method' => 'S256',
    ]))->assertRedirect(url('accounts/sign-in'));
});

it('owns the oauth routes with package controllers', function () {
    $routes = app('router')->getRoutes();

    expect($routes->getByName('oidc.authorize')->getControllerClass())
        ->toBe(AuthorizationController::class)
        ->and($routes->getByName('oidc.approve')->getControllerClass())
        ->toBe(ApproveAuthorizationController::class)
        ->and($routes->getByName('oidc.deny')->getControllerClass())
        ->toBe(DenyAuthorizationController::class);

    expect(collect($routes->getRoutes())->filter(
        fn ($route) => $route->uri() === 'realms/{realm}/oauth/token' && in_array('POST', $route->methods(), true)
    )->count())->toBe(1);
});

it('issues a short-lived access token matching the configured lifetime', function () {
    config(['oidc.token_lifetimes.access_token' => 900]);

    $response = completeAuthorizationCodeFlow($this)->assertOk();

    // expires_in reflects the interactive access-token TTL, not Passport's long default
    expect($response->json('expires_in'))->toBeLessThanOrEqual(900)
        ->and($response->json('expires_in'))->toBeGreaterThan(600);
});

it('pins the context to the login session and its expires_at', function () {
    // seed an oidc session + sid (completeAuthorization acts as the logged-in user)
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $session = OidcSession::query()->find($sid);

    completeAuthorizationCodeFlow($this, [], ['oidc.amr' => ['pwd'], 'oidc.sid' => $sid])->assertOk();

    $context = AuthenticationContext::query()->sole();
    expect($context->sid)->toBe($sid)
        ->and($context->expires_at->getTimestamp())->toBe($session->expires_at->getTimestamp());
});

it('emits the sid claim on fresh issuance and on refresh', function () {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);

    $response = completeAuthorizationCodeFlow($this, [], ['oidc.amr' => ['pwd'], 'oidc.sid' => $sid])->assertOk();
    expect(parseIdToken($response->json('id_token'))->claims()->get('sid'))->toBe($sid);

    $refreshed = $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $response->json('refresh_token'),
    ])->assertOk();
    expect(parseIdToken($refreshed->json('id_token'))->claims()->get('sid'))->toBe($sid);
});

it('records one participant per session-client on authorization', function () {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);

    completeAuthorizationCodeFlow($this, [], ['oidc.amr' => ['pwd'], 'oidc.sid' => $sid])->assertOk();
    completeAuthorizationCodeFlow($this, [], ['oidc.amr' => ['pwd'], 'oidc.sid' => $sid])->assertOk(); // same client again

    expect(app(OidcSessionRepository::class)->participantClientIds($sid))
        ->toBe([$this->client->id]);
});

it('denies refresh after the session is revoked', function () {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $refreshToken = completeAuthorizationCodeFlow($this, [], ['oidc.amr' => ['pwd'], 'oidc.sid' => $sid])->json('refresh_token');

    app(OidcSessionRepository::class)->revoke($sid);

    $this->post('/realms/default/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $refreshToken,
    ])->assertStatus(400);
});
