<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Session\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function () {
    $this->withoutMiddleware([ValidateCsrfToken::class, PreventRequestForgery::class]);
    Passport::authorizationView(fn (array $parameters) => response()->json([
        'authToken' => $parameters['authToken'],
    ]));

    $this->user = User::create(['name' => 'M', 'email' => 'audit@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

it('audits consent approval and token issuance through the code flow', function () {
    $sink = fakeAudit();

    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $this->actingAsIdentity($this->user, authTime: time() - 60)->withSession(['oidc.sid' => $sid]);
    $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid')->response->assertOk();

    $sink->assertRecorded(AuditEventType::ConsentApproved, fn (AuditEvent $event): bool => $event->clientId === (string) $this->client->id
        && $event->userId === (string) $this->user->id
        && $event->context['scopes'] === ['openid']);

    $issued = $sink->assertRecorded(AuditEventType::TokenIssued, fn (AuditEvent $event): bool => $event->context['grant_type'] === 'authorization_code');

    expect($issued->userId)->toBe((string) $this->user->id)
        ->and($issued->clientId)->toBe((string) $this->client->id)
        ->and($issued->sid)->not->toBeNull()
        ->and($issued->context['jti'])->toBeString()
        ->and($issued->context['scopes'])->toBe(['openid']);
});

it('audits a denied consent', function () {
    $sink = fakeAudit();
    $pkce = $this->pkce();

    $view = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get('/oauth/authorize?'.http_build_query([
            'client_id' => $this->client->id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'st4te',
            'code_challenge' => $pkce->challenge,
            'code_challenge_method' => 'S256',
        ]))
        ->assertOk();

    $this->delete(route('oidc.deny'), ['auth_token' => $view->json('authToken')])
        ->assertRedirect();

    $sink->assertRecorded(AuditEventType::ConsentDenied, fn (AuditEvent $event): bool => $event->clientId === (string) $this->client->id
        && $event->userId === (string) $this->user->id);
    $sink->assertNotRecorded(AuditEventType::ConsentApproved);
    $sink->assertNotRecorded(AuditEventType::TokenIssued);
});

it('audits a refresh token grant as token issuance', function () {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $result = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->withSession(['oidc.sid' => $sid])
        ->authorizeAndApprove($this->user, $this->client, scopes: 'openid');

    $sink = fakeAudit();

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'refresh_token' => $result->response->json('refresh_token'),
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
    ])->assertOk();

    $sink->assertRecorded(AuditEventType::TokenIssued, fn (AuditEvent $event): bool => $event->context['grant_type'] === 'refresh_token'
        && $event->userId === (string) $this->user->id
        && $event->sid !== null);
});

it('audits a refresh denied after the session ended', function () {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $result = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->withSession(['oidc.sid' => $sid])
        ->authorizeAndApprove($this->user, $this->client, scopes: 'openid');

    $sink = fakeAudit();
    app(OidcSessionRepository::class)->revoke($sid);

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'refresh_token' => $result->response->json('refresh_token'),
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
    ])->assertStatus(400);

    $sink->assertRecorded(AuditEventType::TokenIssuanceFailed, fn (AuditEvent $event): bool => $event->context['grant_type'] === 'refresh_token'
        && $event->context['reason'] === 'session_ended');
    $sink->assertNotRecorded(AuditEventType::TokenIssued);
});

it('audits a client credentials token issuance', function () {
    $sink = fakeAudit();
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->id,
        'client_secret' => $client->plainSecret,
        'scope' => '',
    ])->assertOk();

    $sink->assertRecorded(AuditEventType::TokenIssued, fn (AuditEvent $event): bool => $event->context['grant_type'] === 'client_credentials'
        && $event->clientId === (string) $client->id
        && $event->userId === null);
});

it('audits a token exchange and its failure paths', function () {
    Passport::tokensCan(['openid' => 'Authenticate', 'orders:read' => 'Read orders']);
    $this->client->forceFill([
        'grant_types' => [...(array) $this->client->getAttribute('grant_types'), TestCase::TOKEN_EXCHANGE_GRANT],
        'allowed_exchange_audiences' => json_encode(['https://api.internal/orders']),
    ])->save();

    $sink = fakeAudit();
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid', 'orders:read']);

    $this->post('/oauth/token', [
        'grant_type' => TestCase::TOKEN_EXCHANGE_GRANT,
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'subject_token' => $subject,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        'audience' => 'https://api.internal/orders',
        'scope' => 'orders:read',
    ])->assertOk();

    $sink->assertRecorded(AuditEventType::TokenIssued, fn (AuditEvent $event): bool => $event->context['grant_type'] === 'urn:ietf:params:oauth:grant-type:token-exchange'
        && $event->userId === (string) $this->user->id
        && $event->context['audience'] === ['https://api.internal/orders']);

    $revoked = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid'], revoked: true);

    $this->post('/oauth/token', [
        'grant_type' => TestCase::TOKEN_EXCHANGE_GRANT,
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'subject_token' => $revoked,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        'audience' => 'https://api.internal/orders',
    ])->assertStatus(400);

    $sink->assertRecorded(AuditEventType::TokenIssuanceFailed, fn (AuditEvent $event): bool => $event->context['reason'] === 'subject_token_invalid'
        && $event->clientId === (string) $this->client->id);
});

it('audits a personal access token issuance', function () {
    $sink = fakeAudit();
    app(ClientRepository::class)->createPersonalAccessGrantClient('PAT', 'users');

    $result = $this->user->createToken('cli', ['openid']);

    $token = $result->getToken();

    $sink->assertRecorded(AuditEventType::TokenIssued, fn (AuditEvent $event): bool => $event->context['grant_type'] === 'personal_access'
        && $event->userId === (string) $this->user->id
        && $event->context['jti'] === (string) $token->getKey());
});

it('audits an access token revocation', function () {
    app(ClientRepository::class)->createPersonalAccessGrantClient('PAT', 'users');
    $result = $this->user->createToken('t', ['openid']);
    $token = $result->getToken();

    if (! $token instanceof Token) {
        throw new RuntimeException('Expected the personal access token to be persisted.');
    }

    $token->forceFill(['client_id' => $this->client->id])->save();

    $sink = fakeAudit();

    $this->postJson('/oauth/revoke', [
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'token' => $result->accessToken,
    ])->assertOk();

    $sink->assertRecorded(AuditEventType::TokenRevoked, fn (AuditEvent $event): bool => $event->clientId === (string) $this->client->id
        && $event->context['token_type_hint'] === 'access_token'
        && $event->context['jti'] === (string) $token->getKey());
});

it('audits a failed client authentication at the introspection endpoint', function () {
    $sink = fakeAudit();

    $this->postJson('/oauth/introspect', [
        'client_id' => $this->client->id,
        'client_secret' => 'wrong-secret',
        'token' => 'irrelevant',
    ])->assertStatus(401);

    $sink->assertRecorded(AuditEventType::ClientAuthenticationFailed, fn (AuditEvent $event): bool => $event->clientId === (string) $this->client->id
        && $event->context['endpoint'] === 'oauth/introspect');
});

it('audits a failed client authentication at the token endpoint', function () {
    $sink = fakeAudit();
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->id,
        'client_secret' => 'wrong-secret',
        'scope' => '',
    ])->assertStatus(401);

    $sink->assertRecorded(AuditEventType::ClientAuthenticationFailed, fn (AuditEvent $event): bool => $event->clientId === (string) $client->id
        && $event->context['endpoint'] === 'oauth/token');
});
