<?php
declare(strict_types=1);

/**
 * OAuth 2.1 (draft-ietf-oauth-v2-1) baseline compliance regressions.
 */

use Bambamboole\LaravelOidc\Tests\TestCase;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    Passport::authorizationView(fn (array $parameters) => response()->json([
        'authToken' => $parameters['authToken'],
        'scopes' => $parameters['scopes'],
    ]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

/**
 * @return array{0: string, 1: string}
 */
function compliancePkcePair(): array
{
    $verifier = str_repeat('v', 64);
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

    return [$verifier, $challenge];
}

/**
 * @param  array<string, mixed>  $overrides
 * @return TestResponse<JsonResponse>
 */
function completeComplianceAuthorization(TestCase $test, array $overrides = []): TestResponse
{
    [$verifier, $challenge] = compliancePkcePair();

    $query = array_merge([
        'client_id' => $test->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid',
        'state' => 'st4te',
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
    ], $overrides);

    $view = $test->actingAs($test->user, 'identity')
        ->withSession(['oidc.auth_time' => time() - 60])
        ->get('/oauth/authorize?'.http_build_query($query))
        ->assertOk();

    $approve = $test->post('/oauth/authorize', ['auth_token' => $view->json('authToken')])
        ->assertRedirect();

    parse_str(parse_url($approve->headers->get('Location'), PHP_URL_QUERY), $params);

    return $test->post('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $test->client->id,
        'client_secret' => $test->client->plainSecret,
        'redirect_uri' => 'https://rp.test/callback',
        'code' => $params['code'],
        'code_verifier' => $verifier,
    ]);
}

// OAuth 2.1 §4.1.3 / §7.5 — exact redirect-URI matching
it('rejects an authorization request whose redirect_uri is not an exact registered match', function () {
    // League's RedirectUriValidator fails the exact-match check via
    // AbstractGrant::validateRedirectUri(), which throws
    // OAuthServerException::invalidClient() — a 401 `invalid_client`,
    // not a 400. It still never redirects to the unvalidated URI.
    $response = $this->actingAs($this->user, 'identity')->get('/oauth/authorize?'.http_build_query([
        'client_id' => $this->client->id,
        'redirect_uri' => 'https://rp.test/callback/extra',
        'response_type' => 'code',
        'scope' => 'openid',
    ]));

    $response->assertStatus(401);
    expect($response->json('error'))->toBe('invalid_client');
});

// OAuth 2.1 §1.5 — the ROPC (password) grant is removed / not supported
it('does not support the password grant', function () {
    $response = $this->post('/oauth/token', [
        'grant_type' => 'password',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'username' => $this->user->getAttribute('email'),
        'password' => 'x',
        'scope' => 'openid',
    ]);

    $response->assertStatus(400);
    expect($response->json('error'))->toBe('unsupported_grant_type');
});

// OAuth 2.1 §4.3.1 — refresh tokens are rotated: the original refresh token is revoked after use
it('rotates refresh tokens: reusing the original refresh token after it has been exchanged fails', function () {
    $refreshToken = completeComplianceAuthorization($this)->assertOk()->json('refresh_token');

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $refreshToken,
    ])->assertOk();

    $reuse = $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'refresh_token' => $refreshToken,
    ]);

    $reuse->assertStatus(400);
    expect($reuse->json('error'))->toBe('invalid_grant');
});
