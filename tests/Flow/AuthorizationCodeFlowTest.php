<?php
declare(strict_types=1);

/**
 * OAuth 2.1 §4.1 authorization code grant + RFC 7636 PKCE (S256); OpenID Connect Core 1.0 §3.1.3 (id_token issuance/validation)
 */

use Bambamboole\LaravelOidc\Auth\AuthenticationMethods;
use Bambamboole\LaravelOidc\Auth\Models\AccessTokenContext;
use Bambamboole\LaravelOidc\Auth\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Auth\Models\OidcSession;
use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Auth\Pipeline\AuthorizationCodeEvent;
use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Bambamboole\LaravelOidc\Facades\Oidc;
use Bambamboole\LaravelOidc\Http\Controllers\ApproveAuthorizationController;
use Bambamboole\LaravelOidc\Http\Controllers\AuthorizationController;
use Bambamboole\LaravelOidc\Http\Controllers\DenyAuthorizationController;
use Bambamboole\LaravelOidc\Testing\InteractsWithOidc;
use Bambamboole\LaravelOidc\Tests\TestCase;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function () {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    Passport::authorizationView(fn (array $parameters) => response()->json([
        'authToken' => $parameters['authToken'],
        'scopes' => $parameters['scopes'],
    ]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

function parseIdToken(string $jwt): UnencryptedToken
{
    $token = (new Parser(new JoseEncoder))->parse($jwt);

    if (! $token instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted JWT.');
    }

    return $token;
}

/**
 * @param  array<string, mixed>  $overrides
 * @param  array<string, mixed>  $session
 * @return TestResponse<JsonResponse>
 */
function completeAuthorization(TestCase $test, array $overrides = [], array $session = []): TestResponse
{
    $test->actingAsIdentity(
        $test->user,
        amr: $session[AuthenticationMethods::SESSION_KEY] ?? [],
        authTime: $session['oidc.auth_time'] ?? time() - 60,
    );

    $extra = array_diff_key($session, array_flip(['oidc.auth_time', AuthenticationMethods::SESSION_KEY]));

    if ($extra !== []) {
        $test->withSession($extra);
    }

    $params = array_merge(['state' => 'st4te', 'nonce' => 'n0nce'], $overrides);

    return $test->authorizeAndApprove($test->user, $test->client, scopes: 'openid email', params: $params)->response;
}

// OIDC Core §3.1.3.6 (at_hash)
it('issues an id_token through the full code + pkce flow', function () {
    config(['app.url' => 'https://op.test', 'oidc.issuer' => null]);

    $response = completeAuthorization($this)->assertOk();

    expect($response->json())->toHaveKeys(['access_token', 'refresh_token', 'id_token']);

    $idToken = parseIdToken($response->json('id_token'));

    expect($idToken->claims()->get('iss'))->toBe('https://op.test')
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
        new Sha256, InMemory::plainText(SigningKeys::publicKey()),
    )))->toBeTrue();

    $jwks = $this->getJson('/.well-known/jwks.json')->json('keys');
    expect($idToken->headers()->get('kid'))->toBe($jwks[0]['kid']);
});

it('merges authorization-code trigger claims into issued and refreshed access tokens', function () {
    Oidc::authorizationCode(function (AuthorizationCodeEvent $event, AccessTokenApi $api): void {
        expect($event->user->getAuthIdentifier())->toBe($this->user->id)
            ->and($event->client->getIdentifier())->toBe((string) $this->client->id)
            ->and($event->scopes)->toBe(['openid', 'email']);

        $api->setAccessTokenClaim('project_id', 'p-1');
        $api->setAccessTokenClaim('via', $event->grantType);
    });

    $response = completeAuthorization($this)->assertOk();
    $accessToken = parseAccessToken((string) $response->json('access_token'));

    expect($accessToken->claims()->get('project_id'))->toBe('p-1')
        ->and($accessToken->claims()->get('via'))->toBe('authorization_code');

    $refreshed = $this->post('/oauth/token', [
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
    $persistedTokenCount = Passport::token()->newQuery()->count();

    Oidc::authorizationCode(function (AuthorizationCodeEvent $event, AccessTokenApi $api): void {
        $api->deny('user_blocked');
    });

    completeAuthorization($this)
        ->assertStatus(401)
        ->assertJsonPath('error', 'access_denied')
        ->assertJsonMissingPath('access_token');

    expect(Passport::token()->newQuery()->count())->toBe($persistedTokenCount);
});

// OIDC Core §3.1.2.1 / §5.4 (openid scope)
it('omits the id_token without the openid scope', function () {
    $response = completeAuthorization($this, ['scope' => 'email'])->assertOk();

    expect($response->json())->toHaveKey('access_token')
        ->and($response->json())->not->toHaveKey('id_token');
});

// OAuth 2.1 §4.3 (refresh) + OIDC Core §12.2 — refresh REISSUES the persisted context
it('reissues amr/acr and claims on refresh, without a fresh nonce', function () {
    $refreshToken = completeAuthorization($this, [], [
        'oidc.amr' => ['pwd', 'otp'],
        'oidc.id_token_claims' => ['groups' => ['admin']],
        'oidc.access_token_claims' => ['tier' => 'gold'],
    ])->json('refresh_token');

    $response = $this->post('/oauth/token', [
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
    $refreshToken = completeAuthorization($this, [], ['oidc.amr' => ['pwd']])->json('refresh_token');

    AuthenticationContext::query()->delete();

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $refreshToken,
    ])->assertStatus(400);
});

it('denies refresh once the session absolute lifetime is exceeded', function () {
    $refreshToken = completeAuthorization($this, [], ['oidc.amr' => ['pwd']])->json('refresh_token');

    AuthenticationContext::query()->update(['expires_at' => now()->subMinute()]);

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $refreshToken,
    ])->assertStatus(400);
});

it('does not leak a denied refresh context into the next refresh on the same grant instance', function () {
    // Octane-safety: the grant is a container singleton, so a stale pendingContext from one
    // request must never survive into the next. Deny one refresh, then reissue a different
    // one on the same AuthorizationServer/grant instance and assert its claims are its own.
    $deniedRefreshToken = completeAuthorization($this, [], ['oidc.amr' => ['pwd']])->json('refresh_token');

    AuthenticationContext::query()->delete();

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $deniedRefreshToken,
    ])->assertStatus(400);

    // A different user avoids Passport's "already granted these scopes" consent skip,
    // which would otherwise short-circuit completeAuthorization() with a redirect.
    $this->user = User::create(['name' => 'N', 'email' => 'n@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    $validRefreshToken = completeAuthorization($this, [], [
        'oidc.amr' => ['pwd', 'otp'],
        'oidc.id_token_claims' => ['groups' => ['ops']],
    ])->json('refresh_token');

    $response = $this->post('/oauth/token', [
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
    $response = completeAuthorization($this, [], ['oidc.amr' => ['pwd', 'otp']])->assertOk();

    $idToken = parseIdToken($response->json('id_token'));
    expect($idToken->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and($idToken->claims()->get('acr'))->toBe('2');
});

it('emits acr "1" for a single-method session', function () {
    $response = completeAuthorization($this, [], ['oidc.amr' => ['pwd']])->assertOk();

    $idToken = parseIdToken($response->json('id_token'));
    expect($idToken->claims()->get('amr'))->toBe(['pwd'])
        ->and($idToken->claims()->get('acr'))->toBe('1');
});

it('omits amr and acr when the session held no methods', function () {
    $idToken = parseIdToken(completeAuthorization($this)->assertOk()->json('id_token'));

    expect($idToken->claims()->has('amr'))->toBeFalse()
        ->and($idToken->claims()->has('acr'))->toBeFalse();
});

// OAuth 2.1 §4.1.1 / §7.6 (PKCE required for every client)
it('rejects an authorization request without PKCE even for a confidential client', function () {
    $response = $this->actingAs($this->user, 'identity')->get('/oauth/authorize?'.http_build_query([
        'client_id' => $this->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid',
        'state' => 'st4te',
    ]));

    // League's invalidRequest() exception never carries a redirect_uri (same
    // as its own public-client PKCE-required path), so this surfaces as a
    // 400 JSON error rather than a redirect back to the client.
    $response->assertStatus(400);
    expect($response->json('error'))->toBe('invalid_request');
});

it('emits postLogin-buffered id_token claims via the context store', function () {
    $response = completeAuthorization($this, [], [
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
    completeAuthorization($this, [], [
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
    $response = completeAuthorization($this, [], [
        'oidc.amr' => ['pwd'],
        'oidc.access_token_claims' => ['tier' => 'gold', 'amr' => ['hax']],
    ])->assertOk();

    $accessToken = parseIdToken($response->json('access_token')); // parses any JWT
    expect($accessToken->claims()->get('tier'))->toBe('gold')
        ->and($accessToken->claims()->has('amr'))->toBeFalse(); // reserved name skipped

    // the issued access token is linked to a context
    expect(AccessTokenContext::query()->count())->toBe(1);
});

// Octane safety: AuthorizationServer (and thus its grants) is a container singleton.
// A stale pendingContext left behind by a *failed* token exchange must never leak
// into a later token request handled by the same grant instance.
it('does not leak a stale pendingContext into a later token request on the same grant instance', function () {
    // First flow: seed a distinguishing access-token claim, then fail the token
    // exchange with a wrong code_verifier so league throws (PKCE mismatch) before
    // issueAccessToken() ever runs — the only place that clears pendingContext.
    $pkce1 = $this->pkce();

    $view1 = $this->actingAsIdentity($this->user, accessTokenClaims: ['leaked' => true], authTime: time() - 60)
        ->get('/oauth/authorize?'.http_build_query([
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

    $approve1 = $this->post('/oauth/authorize', ['auth_token' => $view1->json('authToken')])
        ->assertRedirect();
    parse_str(parse_url($approve1->headers->get('Location'), PHP_URL_QUERY), $params1);

    $this->post('/oauth/token', [
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
        ->get('/oauth/authorize?'.http_build_query([
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

    $approve2 = $this->post('/oauth/authorize', ['auth_token' => $view2->json('authToken')])
        ->assertRedirect();
    parse_str(parse_url($approve2->headers->get('Location'), PHP_URL_QUERY), $params2);

    // Force this request's own context lookup to miss, so the
    // `if ($context !== null)` guard in the grant skips reassigning
    // pendingContext — exactly the condition under which a stale value survives.
    AuthenticationContext::query()->delete();

    $response = $this->post('/oauth/token', [
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

it('owns the oauth routes with package controllers', function () {
    $routes = app('router')->getRoutes();

    expect($routes->getByName('oidc.authorize')->getControllerClass())
        ->toBe(AuthorizationController::class)
        ->and($routes->getByName('oidc.approve')->getControllerClass())
        ->toBe(ApproveAuthorizationController::class)
        ->and($routes->getByName('oidc.deny')->getControllerClass())
        ->toBe(DenyAuthorizationController::class);

    expect(collect($routes->getRoutes())->filter(
        fn ($route) => $route->uri() === 'oauth/token' && in_array('POST', $route->methods(), true)
    )->count())->toBe(1);
});

it('issues a short-lived access token matching the configured lifetime', function () {
    config(['oidc.token_lifetimes.access_token' => 900]);

    $response = completeAuthorization($this)->assertOk();

    // expires_in reflects the interactive access-token TTL, not Passport's long default
    expect($response->json('expires_in'))->toBeLessThanOrEqual(900)
        ->and($response->json('expires_in'))->toBeGreaterThan(600);
});

it('pins the context to the login session and its expires_at', function () {
    // seed an oidc session + sid (completeAuthorization acts as the logged-in user)
    $sid = app(SessionRegistry::class)->start((string) $this->user->id);
    $session = OidcSession::query()->find($sid);

    completeAuthorization($this, [], ['oidc.amr' => ['pwd'], 'oidc.sid' => $sid])->assertOk();

    $context = AuthenticationContext::query()->sole();
    expect($context->sid)->toBe($sid)
        ->and($context->expires_at->getTimestamp())->toBe($session->expires_at->getTimestamp());
});

it('emits the sid claim on fresh issuance and on refresh', function () {
    $sid = app(SessionRegistry::class)->start((string) $this->user->id);

    $response = completeAuthorization($this, [], ['oidc.amr' => ['pwd'], 'oidc.sid' => $sid])->assertOk();
    expect(parseIdToken($response->json('id_token'))->claims()->get('sid'))->toBe($sid);

    $refreshed = $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $response->json('refresh_token'),
    ])->assertOk();
    expect(parseIdToken($refreshed->json('id_token'))->claims()->get('sid'))->toBe($sid);
});

it('records one participant per session-client on authorization', function () {
    $sid = app(SessionRegistry::class)->start((string) $this->user->id);

    completeAuthorization($this, [], ['oidc.amr' => ['pwd'], 'oidc.sid' => $sid])->assertOk();
    completeAuthorization($this, [], ['oidc.amr' => ['pwd'], 'oidc.sid' => $sid])->assertOk(); // same client again

    expect(app(SessionRegistry::class)->participantClientIds($sid))
        ->toBe([$this->client->id]);
});

it('denies refresh after the session is revoked', function () {
    $sid = app(SessionRegistry::class)->start((string) $this->user->id);
    $refreshToken = completeAuthorization($this, [], ['oidc.amr' => ['pwd'], 'oidc.sid' => $sid])->json('refresh_token');

    app(SessionRegistry::class)->revoke($sid);

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $refreshToken,
    ])->assertStatus(400);
});
