<?php

declare(strict_types=1);

/**
 * RFC 8693 (OAuth 2.0 Token Exchange) §2.1–2.2, §3, §4.1 (act); RFC 8707 §2 (resource); RFC 6749 §5.2 (error responses)
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\ExchangeGrantResult;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\ExchangePolicy;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\ExchangeRequest;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\TokenExchanger;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\TokenExchangeEvent;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

const ACCESS_TOKEN_URN = 'urn:ietf:params:oauth:token-type:access_token';

beforeEach(function () {
    config(['oidc.scopes.catalog' => [
        'openid' => 'Authenticate',
        'orders:read' => 'Read orders',
        'orders:write' => 'Write orders',
    ]]);

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    $this->client->forceFill([
        'grant_types' => [...(array) $this->client->getAttribute('grant_types'), TestCase::TOKEN_EXCHANGE_GRANT],
        'allowed_exchange_audiences' => ['https://api.internal/orders'],
    ])->save();
});

/**
 * Posts a token-exchange request for a subject token minted to the test client.
 *
 * @param  list<string>  $subjectScopes
 * @param  array<string, mixed>  $parameters
 * @return TestResponse<Response>
 */
function exchange(TestCase $test, array $parameters = [], array $subjectScopes = ['openid', 'orders:read', 'orders:write'], ?string $subjectToken = null): TestResponse
{
    $subjectToken ??= mintExchangeSubjectToken((string) $test->client->id, (string) $test->user->id, $subjectScopes);

    return $test->post('/realms/default/oauth/token', [
        'grant_type' => TestCase::TOKEN_EXCHANGE_GRANT,
        'client_id' => $test->client->id,
        'client_secret' => $test->client->plainSecret,
        'subject_token' => $subjectToken,
        'subject_token_type' => ACCESS_TOKEN_URN,
        ...$parameters,
    ]);
}

it('exchanges a reciprocal token for a narrowed, audience-scoped access token without an id_token', function () {
    config(['app.url' => 'https://op.test']);

    $response = exchange($this, ['audience' => 'https://api.internal/orders', 'scope' => 'openid orders:read'])->assertOk();

    expect($response->json('issued_token_type'))->toBe(ACCESS_TOKEN_URN)
        ->and($response->json('token_type'))->toBe('Bearer')
        ->and($response->json('scope'))->toBe('openid orders:read')
        ->and($response->json())->not->toHaveKeys(['refresh_token', 'id_token']);

    $at = parseAccessToken($response->json('access_token'));

    expect($at->headers()->get('typ'))->toBe('at+jwt')
        ->and($at->claims()->get('aud'))->toBe(['https://api.internal/orders'])
        ->and($at->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($at->claims()->get('scope'))->toBe('openid orders:read')
        ->and($at->claims()->get('act'))->toBe(['client_id' => $this->client->id]);
});

it('inherits the full subject scope set when scope is omitted', function () {
    $response = exchange($this, ['audience' => 'https://api.internal/orders'])->assertOk();

    expect(explode(' ', (string) $response->json('scope')))->toEqualCanonicalizing(['openid', 'orders:read', 'orders:write'])
        ->and(explode(' ', (string) parseAccessToken($response->json('access_token'))->claims()->get('scope')))
        ->toEqualCanonicalizing(['openid', 'orders:read', 'orders:write']);
});

it('accepts resource in place of audience', function () {
    $response = exchange($this, ['resource' => 'https://api.internal/orders'])->assertOk();

    expect(parseAccessToken((string) $response->json('access_token'))->claims()->get('aud'))->toBe(['https://api.internal/orders']);
});

it('rejects an unusable target with invalid_target', function (array $parameters) {
    exchange($this, $parameters)->assertStatus(400)->assertJsonPath('error', 'invalid_target');
})->with([
    'unlisted audience' => [['audience' => 'https://evil/api']],
    'relative resource' => [['resource' => 'api.internal/orders']],
    'audience and resource disagree' => [['audience' => 'https://api.internal/orders', 'resource' => 'https://api.internal/invoices']],
]);

it('rejects a malformed request with invalid_request', function (array $parameters) {
    exchange($this, $parameters)->assertStatus(400)->assertJsonPath('error', 'invalid_request');
})->with([
    'neither audience nor resource' => [[]],
    'actor_token delegation' => [['audience' => 'https://api.internal/orders', 'actor_token' => 'x', 'actor_token_type' => ACCESS_TOKEN_URN]],
    'wrong subject_token_type' => [['audience' => 'https://api.internal/orders', 'subject_token_type' => 'urn:ietf:params:oauth:token-type:refresh_token']],
]);

it('rejects a subject token that is expired, revoked or not bound to a user with invalid_grant', function (array $subject) {
    $subjectToken = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid'], ...$subject);

    exchange($this, ['audience' => 'https://api.internal/orders'], subjectToken: $subjectToken)
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant')
        ->assertJsonMissingPath('access_token');
})->with([
    'expired' => [['expiresAt' => new DateTimeImmutable('-1 hour')]],
    'revoked' => [['revoked' => true]],
    'userless' => [['userless' => true]],
]);

it('rejects a public client unless it is trusted and registered for the grant', function (bool $trusted, bool $registered, int $status, ?string $error) {
    $public = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Mobile', ['https://rp.test/cb'], confidential: false);
    $public->forceFill([
        'grant_types' => $registered ? [...(array) $public->getAttribute('grant_types'), TestCase::TOKEN_EXCHANGE_GRANT] : $public->getAttribute('grant_types'),
        'allowed_exchange_audiences' => ['https://api.internal/orders'],
    ])->save();
    config(['oidc.clients.trusted' => $trusted ? [(string) $public->getKey()] : []]);

    $response = $this->post('/realms/default/oauth/token', [
        'grant_type' => TestCase::TOKEN_EXCHANGE_GRANT,
        'client_id' => $public->id,
        'subject_token' => mintExchangeSubjectToken((string) $public->id, (string) $this->user->id, ['openid']),
        'subject_token_type' => ACCESS_TOKEN_URN,
        'audience' => 'https://api.internal/orders',
    ])->assertStatus($status);

    if ($error !== null) {
        $response->assertJsonPath('error', $error);
    }
})->with([
    'untrusted' => [false, true, 401, 'invalid_client'],
    'trusted without the grant' => [true, false, 400, 'unauthorized_client'],
    'trusted with the grant' => [true, true, 200, null],
]);

it('runs the token-exchange trigger once with the finalized context and applies its claims', function () {
    $triggerCount = 0;

    app(AccessTokenPipeline::class)->register('token_exchange', function (TokenExchangeEvent $event, AccessTokenApi $api) use (&$triggerCount): void {
        $triggerCount++;

        expect($event->user->getAuthIdentifier())->toBe($this->user->getAuthIdentifier())
            ->and((string) $event->client->getKey())->toBe((string) $this->client->id)
            ->and($event->scopes)->toBe(['orders:read'])
            ->and($event->audience)->toBe('https://api.internal/orders')
            ->and($event->subjectClaims['sub'] ?? null)->toBe((string) $this->user->id);

        $api->setAccessTokenClaim('tenant', 'acme');
    });

    $response = exchange($this, ['audience' => 'https://api.internal/orders', 'scope' => 'orders:read'])->assertOk();

    expect($triggerCount)->toBe(1)
        ->and(parseAccessToken((string) $response->json('access_token'))->claims()->get('tenant'))->toBe('acme');
});

it('denies the exchange before persisting when a trigger denies', function () {
    app(AccessTokenPipeline::class)->register('token_exchange', fn (TokenExchangeEvent $event, AccessTokenApi $api) => $api->deny('exchange_blocked'));
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid']);
    $persisted = AccessToken::query()->count();

    exchange($this, ['audience' => 'https://api.internal/orders'], subjectToken: $subject)
        ->assertStatus(400)
        ->assertJsonPath('error', 'access_denied')
        ->assertJsonMissingPath('access_token');

    expect(AccessToken::query()->count())->toBe($persisted);
});

it('keeps the package-owned actor chain when a trigger attempts to replace it', function () {
    $root = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid', 'orders:read']);
    $chained = app(TokenExchanger::class)->exchange($root, $this->client, 'https://api.internal/orders', ['orders:read'])->toString();

    app(AccessTokenPipeline::class)->register('token_exchange', fn (TokenExchangeEvent $event, AccessTokenApi $api) => $api->setAccessTokenClaim('act', ['client_id' => 'forged-client']));

    $response = exchange($this, ['audience' => 'https://api.internal/orders', 'scope' => 'orders:read'], subjectToken: $chained)->assertOk();

    expect(parseAccessToken((string) $response->json('access_token'))->claims()->get('act'))->toBe([
        'client_id' => $this->client->id,
        'act' => ['client_id' => $this->client->id],
    ]);
});

it('hands extension parameters to the exchange policy and its context to the trigger', function () {
    $policy = new class implements ExchangePolicy
    {
        public ?ExchangeRequest $request = null;

        public function authorize(ExchangeRequest $request): ExchangeGrantResult
        {
            $this->request = $request;

            return new ExchangeGrantResult(
                userId: (string) $request->subjectClaims['sub'],
                scopes: [],
                audience: [(string) $request->requestedAudience],
                expiresAt: $request->subjectExpiresAt,
                context: ['tenant_id' => $request->parameters['tenant'] ?? null],
            );
        }
    };
    app()->instance(ExchangePolicy::class, $policy);

    app(AccessTokenPipeline::class)->register('token_exchange', fn (TokenExchangeEvent $event, AccessTokenApi $api) => $api->setAccessTokenClaim('tenant_id', $api->context('tenant_id')));

    $response = exchange($this, ['audience' => 'https://api.internal/orders', 'tenant' => 'acme'])->assertOk();

    expect($policy->request?->parameters)->toBe(['tenant' => 'acme'])
        ->and(parseAccessToken((string) $response->json('access_token'))->claims()->get('tenant_id'))->toBe('acme');
});
