<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Consents\ConsentRepository;
use Bambamboole\LaravelOidc\Server\Consents\Models\Consent;
use Bambamboole\LaravelOidc\Server\Shared\Consents\ConsentStore;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenRevoker;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Bambamboole\LaravelOidc\Server\Testing\PkcePair;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
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
 * A bare authorize request: the consent view (200) when consent is needed,
 * the code redirect when it is not.
 *
 * @return TestResponse<Response>
 */
function authorizeExpectingDecision(TestCase $test, string $scopes = 'openid'): TestResponse
{
    return $test->actingAsIdentity($test->user, authTime: time() - 60)
        ->get(route('oidc.authorize').'?'.http_build_query([
            'client_id' => $test->client->client_id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => $scopes,
            'state' => 'st4te',
            'code_challenge' => PkcePair::generate()->challenge,
            'code_challenge_method' => 'S256',
        ]));
}

function storedConsent(TestCase $test): ?Consent
{
    return app(ConsentRepository::class)->find((string) $test->user->id, $test->client);
}

it('records the approved scopes as a consent', function () {
    $this->authorizeAndApprove($this->user, $this->client, 'openid email');

    expect(storedConsent($this))->not->toBeNull()
        ->and(storedConsent($this)?->scopes)->toBe(['openid', 'email'])
        ->and(storedConsent($this)?->revoked_at)->toBeNull();
});

it('does not record a consent when the user denies', function () {
    $view = authorizeExpectingDecision($this)->assertOk();

    $this->delete(route('oidc.deny'), ['auth_token' => $view->json('authToken')])->assertRedirect();

    expect(storedConsent($this))->toBeNull();
});

it('skips the consent screen once the tokens it led to have expired', function () {
    $this->authorizeAndApprove($this->user, $this->client);

    Token::query()->update(['expires_at' => now()->subHour()]);

    authorizeExpectingDecision($this)->assertRedirect();
});

it('keeps the consent when the tokens are revoked', function () {
    $result = $this->authorizeAndApprove($this->user, $this->client);

    app(AccessTokenRevoker::class)->revoke((string) parseAccessToken($result->accessToken)->claims()->get('jti'));

    expect(Token::query()->where('revoked', false)->exists())->toBeFalse();

    authorizeExpectingDecision($this)->assertRedirect();
});

it('shows the consent screen again after the consent was withdrawn', function () {
    $this->authorizeAndApprove($this->user, $this->client);

    app(ConsentRepository::class)->revoke((string) $this->user->id, $this->client);

    authorizeExpectingDecision($this)->assertOk();
    expect(storedConsent($this)?->revoked_at)->not->toBeNull();
});

it('re-activates a withdrawn consent on the next approval', function () {
    $this->authorizeAndApprove($this->user, $this->client);
    app(ConsentRepository::class)->revoke((string) $this->user->id, $this->client);

    $this->authorizeAndApprove($this->user, $this->client);

    expect(Consent::query()->count())->toBe(1)
        ->and(storedConsent($this)?->revoked_at)->toBeNull();
});

it('asks again for a scope the consent does not cover and merges it in', function () {
    $this->authorizeAndApprove($this->user, $this->client);

    authorizeExpectingDecision($this, 'openid email')->assertOk();

    $this->authorizeAndApprove($this->user, $this->client, 'openid email');

    expect(storedConsent($this)?->scopes)->toBe(['openid', 'email']);

    authorizeExpectingDecision($this, 'email')->assertRedirect();
    authorizeExpectingDecision($this, 'openid')->assertRedirect();
});

it('always shows the screen for prompt=consent', function () {
    $this->authorizeAndApprove($this->user, $this->client);

    $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get(route('oidc.authorize').'?'.http_build_query([
            'client_id' => $this->client->client_id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'st4te',
            'prompt' => 'consent',
            'code_challenge' => PkcePair::generate()->challenge,
            'code_challenge_method' => 'S256',
        ]))
        ->assertOk();
});

it('keeps consents per user', function () {
    $this->authorizeAndApprove($this->user, $this->client);

    $this->user = User::create(['name' => 'N', 'email' => 'n@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    authorizeExpectingDecision($this)->assertOk();
});

it('grants through the store idempotently', function () {
    $store = app(ConsentStore::class);
    $userId = (string) $this->user->id;
    $clientKey = (string) $this->client->getKey();

    $store->grant($userId, $clientKey, ['openid']);
    $store->grant($userId, $clientKey, ['openid', 'profile']);

    expect(Consent::query()->count())->toBe(1)
        ->and($store->covers($userId, $clientKey, ['profile', 'openid']))->toBeTrue()
        ->and($store->covers($userId, $clientKey, ['email']))->toBeFalse()
        ->and($store->covers($userId, $clientKey, []))->toBeTrue()
        ->and($store->covers($userId, 'unknown-client', []))->toBeFalse();
});
