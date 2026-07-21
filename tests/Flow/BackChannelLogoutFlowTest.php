<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Bambamboole\LaravelOidc\BackChannel\SendBackChannelLogout;
use Bambamboole\LaravelOidc\Session\EndOidcSession;
use Bambamboole\LaravelOidc\Tests\TestCase;
use Illuminate\Auth\Events\Logout;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Bus;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Workbench\App\Models\User;

it('revokes the session and fans out on the Logout event', function () {
    Bus::fake();
    $this->startSession();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $sid = app(SessionRegistry::class)->start((string) $user->id);
    session()->put('oidc.sid', $sid);

    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('A', ['https://a.test/cb']);
    $client->forceFill(['backchannel_logout_uri' => 'https://a.test/bclo'])->save();
    app(SessionRegistry::class)->recordParticipant($sid, (string) $client->id);

    app(EndOidcSession::class)->handle(new Logout(config('passport.guard'), $user));

    expect(app(SessionRegistry::class)->find($sid)->revoked_at)->not->toBeNull();
    Bus::assertDispatchedTimes(SendBackChannelLogout::class, 1);
});

/**
 * @return TestResponse<JsonResponse>
 */
function completeBackChannelLogoutAuthorization(TestCase $test, string $sid): TestResponse
{
    $verifier = str_repeat('v', 64);
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

    $view = $test->actingAs($test->user, 'identity')
        ->withSession(['oidc.auth_time' => time() - 60, 'oidc.amr' => ['pwd'], 'oidc.sid' => $sid])
        ->get('/oauth/authorize?'.http_build_query([
            'client_id' => $test->client->id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'st4te',
            'nonce' => 'n0nce',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))
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

describe('via /oauth/logout', function () {
    beforeEach(function () {
        $this->withoutMiddleware(ValidateCsrfToken::class);
        Passport::authorizationView(fn (array $parameters) => response()->json([
            'authToken' => $parameters['authToken'],
        ]));

        $this->user = User::create(['name' => 'RP User', 'email' => 'rp-user@example.com', 'email_verified_at' => now(), 'password' => 'x']);
        $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
        $this->client->forceFill(['backchannel_logout_uri' => 'https://rp.test/bclo'])->save();
    });

    it('revokes the session and fans out when a valid id_token_hint carries the sid', function () {
        Bus::fake();

        $sid = app(SessionRegistry::class)->start((string) $this->user->id);
        app(SessionRegistry::class)->recordParticipant($sid, (string) $this->client->id);

        $idToken = completeBackChannelLogoutAuthorization($this, $sid)->assertOk()->json('id_token');

        $this->actingAs($this->user, 'identity')
            ->post('/oauth/logout', ['id_token_hint' => $idToken])
            ->assertRedirect();

        expect(app(SessionRegistry::class)->find($sid)->revoked_at)->not->toBeNull();
        Bus::assertDispatchedTimes(SendBackChannelLogout::class, 1);
    });
});
