<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Consents\ConsentRepository;
use Bambamboole\LaravelOidc\Server\Consents\Models\Consent;
use Bambamboole\LaravelOidc\Server\Scopes\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Bambamboole\LaravelOidc\Server\Shared\Consents\ConsentStore;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenRevoker;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\RealmAudiences;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Bambamboole\LaravelOidc\Server\Testing\PkcePair;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Collection;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function (): void {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

/**
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

/** No `resource` was requested, so the consent belongs to the realm itself. */
function realmResource(): string
{
    return app(RealmAudiences::class)->default()[0];
}

function storedConsent(TestCase $test): ?Consent
{
    return app(ConsentRepository::class)->find((string) $test->user->id, $test->client, realmResource());
}

it('records the approved scopes as a consent', function (): void {
    $this->authorizeAndApprove($this->user, $this->client, 'openid email');

    expect(storedConsent($this))->not->toBeNull()
        ->and(storedConsent($this)?->scopes)->toBe(['openid', 'email'])
        ->and(storedConsent($this)?->revoked_at)->toBeNull();
});

it('does not record a consent when the user denies', function (): void {
    $view = authorizeExpectingDecision($this)->assertOk();

    $this->delete(route('oidc.deny'), ['auth_token' => $view->json('authToken')])->assertRedirect();

    expect(storedConsent($this))->toBeNull();
});

it('skips the consent screen once the tokens it led to have expired', function (): void {
    $this->authorizeAndApprove($this->user, $this->client);

    AccessToken::query()->update(['expires_at' => now()->subHour()]);

    authorizeExpectingDecision($this)->assertRedirect();
});

it('keeps the consent when the tokens are revoked', function (): void {
    $result = $this->authorizeAndApprove($this->user, $this->client);

    app(AccessTokenRevoker::class)->revoke((string) parseAccessToken($result->accessToken)->claims()->get('jti'));

    expect(AccessToken::query()->where('revoked', false)->exists())->toBeFalse();

    authorizeExpectingDecision($this)->assertRedirect();
});

it('shows the consent screen again after the consent was withdrawn', function (): void {
    $this->authorizeAndApprove($this->user, $this->client);

    app(ConsentRepository::class)->revoke((string) $this->user->id, $this->client);

    authorizeExpectingDecision($this)->assertOk();
    expect(storedConsent($this)?->revoked_at)->not->toBeNull();
});

it('re-activates a withdrawn consent on the next approval', function (): void {
    $this->authorizeAndApprove($this->user, $this->client);
    app(ConsentRepository::class)->revoke((string) $this->user->id, $this->client);

    $this->authorizeAndApprove($this->user, $this->client);

    expect(Consent::query()->count())->toBe(1)
        ->and(storedConsent($this)?->revoked_at)->toBeNull();
});

it('asks again for a scope the consent does not cover and merges it in', function (): void {
    $this->authorizeAndApprove($this->user, $this->client);

    authorizeExpectingDecision($this, 'openid email')->assertOk();

    $this->authorizeAndApprove($this->user, $this->client, 'openid email');

    expect(storedConsent($this)?->scopes)->toBe(['openid', 'email']);

    authorizeExpectingDecision($this, 'email')->assertRedirect();
    authorizeExpectingDecision($this, 'openid')->assertRedirect();
});

it('always shows the screen for prompt=consent', function (): void {
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

it('keeps consents per user', function (): void {
    $this->authorizeAndApprove($this->user, $this->client);

    $this->user = User::create(['name' => 'N', 'email' => 'n@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    authorizeExpectingDecision($this)->assertOk();
});

it('grants through the store idempotently', function (): void {
    $store = app(ConsentStore::class);
    $userId = (string) $this->user->id;
    $clientKey = (string) $this->client->getKey();

    $realm = [realmResource()];

    $store->grant($userId, $clientKey, ['openid'], $realm);
    $store->grant($userId, $clientKey, ['openid', 'profile'], $realm);

    expect(Consent::query()->count())->toBe(1)
        ->and($store->covers($userId, $clientKey, ['profile', 'openid'], $realm))->toBeTrue()
        ->and($store->covers($userId, $clientKey, ['email'], $realm))->toBeFalse()
        ->and($store->covers($userId, $clientKey, [], $realm))->toBeTrue()
        ->and($store->covers($userId, $clientKey, [], ['https://other.test']))->toBeFalse()
        ->and($store->covers($userId, $clientKey, [], []))->toBeFalse()
        ->and($store->covers($userId, 'unknown-client', [], $realm))->toBeFalse();
});

function fakeConsentViewListingScopes(): void
{
    fakeConsentViewUsing(fn (array $parameters) => response()->json([
        'authToken' => $parameters['authToken'],
        'scopes' => array_map(fn (Scope $scope): string => $scope->id, $parameters['scopes']),
    ]));
}

it('shows the client default scopes on the consent screen even when not requested', function (): void {
    $this->client->forceFill(['default_scopes' => ['email']])->save();
    fakeConsentViewListingScopes();

    authorizeExpectingDecision($this)->assertOk()->assertJson(['scopes' => ['openid', 'email']]);
});

it('stores the client default scopes in the consent and skips the screen once they are covered', function (): void {
    $this->client->forceFill(['default_scopes' => ['email']])->save();

    $this->authorizeAndApprove($this->user, $this->client);

    expect(storedConsent($this)?->scopes)->toBe(['openid', 'email']);

    authorizeExpectingDecision($this)->assertRedirect();
    authorizeExpectingDecision($this, 'openid email')->assertRedirect();
});

it('never shows a hidden scope on the consent screen while still granting it', function (): void {
    $hidden = new Scope('internal', 'Internal', hidden: true);

    app()->extend(ScopeRepository::class, fn (ScopeRepository $inner): ScopeRepository => new readonly class($inner, $hidden) implements ScopeRepository
    {
        public function __construct(private ScopeRepository $inner, private Scope $hidden) {}

        public function all(array $audiences = []): Collection
        {
            return $this->inner->all($audiences)->push($this->hidden);
        }

        public function find(string $identifier, array $audiences = []): ?Scope
        {
            return $identifier === $this->hidden->id ? $this->hidden : $this->inner->find($identifier, $audiences);
        }

        public function finalize(array $requested, string $grantType, ?Client $client, ?string $userIdentifier = null, array $audiences = []): array
        {
            return array_values(array_filter($requested, fn (Scope $scope): bool => $this->find($scope->id, $audiences) instanceof Scope));
        }
    });

    $this->client->forceFill(['default_scopes' => ['internal']])->save();
    fakeConsentViewListingScopes();

    authorizeExpectingDecision($this)->assertOk()->assertJson(['scopes' => ['openid']]);

    $result = $this->authorizeAndApprove($this->user, $this->client);

    expect($result->response->json('scope'))->toBe('openid internal')
        ->and(storedConsent($this)?->scopes)->toBe(['openid', 'internal']);
});
