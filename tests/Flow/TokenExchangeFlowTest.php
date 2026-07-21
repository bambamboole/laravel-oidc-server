<?php

declare(strict_types=1);

/**
 * RFC 8693 (OAuth 2.0 Token Exchange); RFC 6749 §5.2 (error responses)
 */

use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Auth\Pipeline\TokenExchangeEvent;
use Bambamboole\LaravelOidc\Exchange\TokenExchanger;
use Bambamboole\LaravelOidc\Facades\Oidc;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Workbench\App\Models\User;

const EXCHANGE_URN = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_URN = 'urn:ietf:params:oauth:token-type:access_token';

beforeEach(function () {
    Passport::tokensCan([
        'openid' => 'Authenticate',
        'orders:read' => 'Read orders',
        'orders:write' => 'Write orders',
    ]);

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    $this->client->forceFill([
        'grant_types' => [...(array) $this->client->getAttribute('grant_types'), EXCHANGE_URN],
        'allowed_exchange_audiences' => json_encode(['https://api.internal/orders']),
    ])->save();
    $this->secret = $this->client->plainSecret;
});

// RFC 8693 §2.1–2.2, §4.1 (act)
it('exchanges a reciprocal token for a narrowed, audience-scoped access token', function () {
    config(['app.url' => 'https://op.test']);
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid', 'orders:read', 'orders:write']);

    $response = $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN,
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'subject_token' => $subject,
        'subject_token_type' => ACCESS_TOKEN_URN,
        'audience' => 'https://api.internal/orders',
        'scope' => 'orders:read',
    ])->assertOk();

    expect($response->json('issued_token_type'))->toBe(ACCESS_TOKEN_URN)
        ->and($response->json('token_type'))->toBe('Bearer')
        ->and($response->json('scope'))->toBe('orders:read')
        ->and($response->json())->not->toHaveKey('refresh_token');

    $at = parseAccessToken($response->json('access_token'));
    expect($at->headers()->get('typ'))->toBe('at+jwt')
        ->and($at->claims()->get('aud'))->toBe(['https://api.internal/orders'])
        ->and($at->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($at->claims()->get('scope'))->toBe('orders:read')
        ->and($at->claims()->get('act'))->toBe(['client_id' => $this->client->id]);
});

it('runs the token-exchange trigger once with finalized context and applies its access-token claims', function () {
    $triggerCount = 0;

    Oidc::tokenExchange(function (TokenExchangeEvent $event, AccessTokenApi $api) use (&$triggerCount): void {
        $triggerCount++;

        expect($event->user->getAuthIdentifier())->toBe($this->user->getAuthIdentifier())
            ->and($event->client->getIdentifier())->toBe((string) $this->client->id)
            ->and($event->scopes)->toBe(['orders:read'])
            ->and($event->audience)->toBe('https://api.internal/orders')
            ->and($event->subjectClaims['sub'] ?? null)->toBe((string) $this->user->id);

        $api->setAccessTokenClaim('tenant', 'acme');
    });

    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid', 'orders:read', 'orders:write']);

    $response = $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN,
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'subject_token' => $subject,
        'subject_token_type' => ACCESS_TOKEN_URN,
        'audience' => 'https://api.internal/orders',
        'scope' => 'orders:read',
    ])->assertOk();

    $claims = parseAccessToken((string) $response->json('access_token'))->claims()->all();

    expect($triggerCount)->toBe(1)
        ->and($claims)->toHaveKey('tenant', 'acme');
});

it('denies token exchange before persisting an access token', function () {
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid', 'orders:read']);
    $persistedTokenCount = Passport::token()->newQuery()->count();

    Oidc::tokenExchange(function (TokenExchangeEvent $event, AccessTokenApi $api): void {
        $api->deny('exchange_blocked');
    });

    $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN,
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'subject_token' => $subject,
        'subject_token_type' => ACCESS_TOKEN_URN,
        'audience' => 'https://api.internal/orders',
        'scope' => 'orders:read',
    ])->assertStatus(401)
        ->assertJsonPath('error', 'access_denied')
        ->assertJsonMissingPath('access_token');

    expect(Passport::token()->newQuery()->count())->toBe($persistedTokenCount);
});

it('keeps the package-owned actor chain when a token-exchange trigger attempts to replace it', function () {
    $rootSubject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid', 'orders:read']);
    $subject = app(TokenExchanger::class)
        ->exchange($rootSubject, $this->client, 'https://api.internal/orders', ['orders:read'])
        ->toString();
    $triggerCount = 0;

    Oidc::tokenExchange(function (TokenExchangeEvent $event, AccessTokenApi $api) use (&$triggerCount): void {
        $triggerCount++;
        $api->setAccessTokenClaim('act', ['client_id' => 'forged-client']);
    });

    $response = $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN,
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'subject_token' => $subject,
        'subject_token_type' => ACCESS_TOKEN_URN,
        'audience' => 'https://api.internal/orders',
        'scope' => 'orders:read',
    ])->assertOk();

    $accessToken = parseAccessToken((string) $response->json('access_token'));

    expect($triggerCount)->toBe(1)
        ->and($accessToken->claims()->get('act'))->toBe([
            'client_id' => $this->client->id,
            'act' => ['client_id' => $this->client->id],
        ]);
});

it('inherits the subject token full scope set when the scope param is omitted', function () {
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid', 'orders:read', 'orders:write']);

    $response = $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN,
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'subject_token' => $subject,
        'subject_token_type' => ACCESS_TOKEN_URN,
        'audience' => 'https://api.internal/orders',
    ])->assertOk();

    expect($response->json('scope'))->not->toBeEmpty();
    expect(explode(' ', (string) $response->json('scope')))->toEqualCanonicalizing(['openid', 'orders:read', 'orders:write']);

    $at = parseAccessToken($response->json('access_token'));
    expect(explode(' ', (string) $at->claims()->get('scope')))->toEqualCanonicalizing(['openid', 'orders:read', 'orders:write']);
});

// RFC 8693 §2.2.2 (invalid_target)
it('rejects an unlisted audience with invalid_target', function () {
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid']);
    $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN, 'client_id' => $this->client->id, 'client_secret' => $this->secret,
        'subject_token' => $subject, 'subject_token_type' => ACCESS_TOKEN_URN, 'audience' => 'https://evil/api',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');
});

// RFC 8693 §2.2.2 + RFC 6749 §5.2 (invalid_grant)
it('rejects an expired subject token with invalid_grant', function () {
    $subject = mintExchangeSubjectToken(
        (string) $this->client->id,
        (string) $this->user->id,
        ['openid'],
        expiresAt: new DateTimeImmutable('-1 hour'),
    );

    $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN,
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'subject_token' => $subject,
        'subject_token_type' => ACCESS_TOKEN_URN,
        'audience' => 'https://api.internal/orders',
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant')
        ->assertJsonMissingPath('access_token');
});

// RFC 8693 §2.2.2 + RFC 6749 §5.2 (invalid_grant)
it('rejects a revoked subject token with invalid_grant', function () {
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid'], revoked: true);

    $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN,
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'subject_token' => $subject,
        'subject_token_type' => ACCESS_TOKEN_URN,
        'audience' => 'https://api.internal/orders',
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant')
        ->assertJsonMissingPath('access_token');
});

// RFC 8693 §2.2.2 + RFC 6749 §5.2 (invalid_grant)
it('rejects a subject token not bound to a user with invalid_grant', function () {
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid'], userless: true);

    $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN,
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'subject_token' => $subject,
        'subject_token_type' => ACCESS_TOKEN_URN,
        'audience' => 'https://api.internal/orders',
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant')
        ->assertJsonMissingPath('access_token');
});

it('never mints an id_token even when the exchange requests scope openid', function () {
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid', 'orders:read']);

    $response = $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN,
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'subject_token' => $subject,
        'subject_token_type' => ACCESS_TOKEN_URN,
        'audience' => 'https://api.internal/orders',
        'scope' => 'openid',
    ])->assertOk();

    $response->assertJsonMissingPath('id_token');
    expect($response->json('access_token'))->not->toBeNull()
        ->and($response->json('issued_token_type'))->toBe(ACCESS_TOKEN_URN);
});

it('rejects a public client with invalid_client', function () {
    $public = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Public', ['https://p/cb'], confidential: false);
    $public->forceFill([
        'grant_types' => [...(array) $public->getAttribute('grant_types'), EXCHANGE_URN],
        'allowed_exchange_audiences' => json_encode(['https://api.internal/orders']),
    ])->save();
    $subject = mintExchangeSubjectToken((string) $public->id, (string) $this->user->id, ['openid']);

    $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN,
        'client_id' => $public->id,
        'subject_token' => $subject,
        'subject_token_type' => ACCESS_TOKEN_URN,
        'audience' => 'https://api.internal/orders',
    ])->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

// RFC 8693 §3 (token type identifiers)
it('rejects a wrong subject_token_type with invalid_request', function () {
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid']);

    $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN,
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'subject_token' => $subject,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:refresh_token',
        'audience' => 'https://api.internal/orders',
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

it('rejects a client without the grant', function () {
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://o/cb']);
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid']);
    $this->post('/oauth/token', [
        'grant_type' => EXCHANGE_URN, 'client_id' => $other->id, 'client_secret' => $other->plainSecret,
        'subject_token' => $subject, 'subject_token_type' => ACCESS_TOKEN_URN, 'audience' => 'https://api.internal/orders',
    ])->assertStatus(400);
});

// RFC 8414 §2 (grant_types_supported)
it('advertises the grant in discovery when enabled', function () {
    expect($this->getJson('/.well-known/openid-configuration')->json('grant_types_supported'))
        ->toContain(EXCHANGE_URN);
});

it('omits the grant from discovery when disabled', function () {
    config(['oidc.token_exchange.enabled' => false]);

    expect($this->getJson('/.well-known/openid-configuration')->json('grant_types_supported'))
        ->not->toContain(EXCHANGE_URN);
});
