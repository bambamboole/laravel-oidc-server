<?php

declare(strict_types=1);

/**
 * OAuth 2.1 §4.1 authorization code grant + RFC 7636 PKCE (S256); OpenID Connect Core 1.0 §2 (acr, amr),
 * §3.1.3 (token response), §3.1.3.6 (at_hash); OpenID Connect Back-Channel Logout §2.1 (sid)
 */

use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginApi;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
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

beforeEach(function (): void {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => bcrypt('secret-password')]);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

/**
 * @param  list<string>  $amr
 * @param  array<string, mixed>  $idTokenClaims
 * @param  array<string, mixed>  $accessTokenClaims
 * @param  array<string, mixed>  $params
 * @return TestResponse<JsonResponse>
 */
function completeAuthorizationCodeFlow(
    TestCase $test,
    array $amr = [],
    array $idTokenClaims = [],
    array $accessTokenClaims = [],
    ?string $sid = null,
    string $scopes = 'openid email',
    array $params = [],
): TestResponse {
    $test->actingAsIdentity($test->user, idTokenClaims: $idTokenClaims, accessTokenClaims: $accessTokenClaims, amr: $amr, authTime: time() - 60);

    if ($sid !== null) {
        $test->withSession(['oidc.sid' => $sid]);
    }

    return $test->authorizeAndApprove($test->user, $test->client, scopes: $scopes, params: ['state' => 'st4te', 'nonce' => 'n0nce', ...$params])->response;
}

it('issues a signed id_token and access token through the code + PKCE flow', function (): void {
    config(['app.url' => 'https://op.test', 'oidc.issuer' => null]);

    $response = completeAuthorizationCodeFlow($this)->assertOk();

    expect($response->json())->toHaveKeys(['access_token', 'refresh_token', 'id_token']);

    $idToken = parseIdToken($response->json('id_token'));
    $expectedAtHash = rtrim(strtr(base64_encode(substr(hash('sha256', $response->json('access_token'), true), 0, 16)), '+/', '-_'), '=');

    expect($idToken->claims()->get('iss'))->toBe('https://op.test/realms/default')
        ->and($idToken->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($idToken->claims()->get('aud'))->toBe([$this->client->id])
        ->and($idToken->claims()->get('nonce'))->toBe('n0nce')
        ->and($idToken->claims()->get('auth_time'))->toBeInt()
        ->and($idToken->claims()->get('email'))->toBe('m@example.com')
        ->and($idToken->claims()->get('at_hash'))->toBe($expectedAtHash)
        ->and((new Validator)->validate($idToken, new SignedWith(new Sha256, InMemory::plainText(signingPublicKey()))))->toBeTrue()
        ->and($idToken->headers()->get('kid'))->toBe($this->getJson('/realms/default/.well-known/jwks.json')->json('keys.0.kid'));
});

it('omits the id_token without the openid scope', function (): void {
    $response = completeAuthorizationCodeFlow($this, scopes: 'email')->assertOk();

    expect($response->json())->toHaveKey('access_token')
        ->and($response->json())->not->toHaveKey('id_token');
});

it('carries the login session amr, derived acr and postLogin claims into the issued tokens', function (): void {
    $response = completeAuthorizationCodeFlow(
        $this,
        amr: ['pwd', 'otp'],
        idTokenClaims: ['groups' => ['admin']],
        accessTokenClaims: ['tier' => 'gold', 'amr' => ['hax']],
    )->assertOk();

    $idToken = parseIdToken($response->json('id_token'));
    $accessToken = parseAccessToken($response->json('access_token'));

    expect($idToken->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and($idToken->claims()->get('acr'))->toBe('2')
        ->and($idToken->claims()->get('groups'))->toBe(['admin'])
        ->and($accessToken->claims()->get('tier'))->toBe('gold')
        ->and($accessToken->claims()->has('amr'))->toBeFalse();
});

it('omits amr and acr when the login session recorded no methods', function (): void {
    $idToken = parseIdToken(completeAuthorizationCodeFlow($this)->assertOk()->json('id_token'));

    expect($idToken->claims()->has('amr'))->toBeFalse()
        ->and($idToken->claims()->has('acr'))->toBeFalse();
});

it('carries a real credential login and its postLogin claims through to the id_token', function (): void {
    app(PostLoginPipeline::class)->register(fn (LoginEvent $event, LoginApi $api) => $api->setIdTokenClaim('groups', ['admin']));

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])->assertRedirect();

    $idToken = parseIdToken($this->authorizeAndApprove($this->user, $this->client, scopes: 'openid')->idToken);

    expect($idToken->claims()->get('groups'))->toBe(['admin'])
        ->and($idToken->claims()->get('amr'))->toBe(['pwd'])
        ->and($idToken->claims()->get('acr'))->toBe('1');
});

it('emits the sid claim and records the client as a session participant', function (): void {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);

    $response = completeAuthorizationCodeFlow($this, amr: ['pwd'], sid: $sid)->assertOk();
    completeAuthorizationCodeFlow($this, amr: ['pwd'], sid: $sid)->assertOk();

    expect(parseIdToken($response->json('id_token'))->claims()->get('sid'))->toBe($sid)
        ->and(app(OidcSessionRepository::class)->participantClientIds($sid))->toBe([$this->client->id]);
});

it('applies authorization-code trigger claims to the issued access token', function (): void {
    app(AccessTokenPipeline::class)->register('authorization_code', function (AuthorizationCodeEvent $event, AccessTokenApi $api): void {
        expect($event->user->getAuthIdentifier())->toBe($this->user->id)
            ->and((string) $event->client->getKey())->toBe((string) $this->client->id)
            ->and($event->scopes)->toBe(['openid', 'email']);

        $api->setAccessTokenClaim('project_id', 'p-1');
        $api->setAccessTokenClaim('via', $event->grantType);
    });

    $accessToken = parseAccessToken((string) completeAuthorizationCodeFlow($this)->assertOk()->json('access_token'));

    expect($accessToken->claims()->get('project_id'))->toBe('p-1')
        ->and($accessToken->claims()->get('via'))->toBe('authorization_code');
});

it('denies issuance before persisting when a trigger denies', function (): void {
    app(AccessTokenPipeline::class)->register('authorization_code', fn (AuthorizationCodeEvent $event, AccessTokenApi $api) => $api->deny('user_blocked'));

    completeAuthorizationCodeFlow($this)
        ->assertStatus(400)
        ->assertJsonPath('error', 'access_denied')
        ->assertJsonMissingPath('access_token');

    expect(AccessToken::query()->count())->toBe(0);
});
