<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Sessions\BackChannel\BackChannelLogoutNotifier;
/**
 * A client has two identities: the primary key that foreign keys point at, and the
 * `client_id` relying parties send. Everything that leaves the process carries the
 * latter, so renaming a client never touches its tokens.
 */

use Bambamboole\LaravelOidc\Server\Sessions\BackChannel\SendBackChannelLogout;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\Events\TokenIssued;
use Bambamboole\LaravelOidc\Server\Tokens\Events\TokenRevoked;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\Queue;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function (): void {
    $this->withoutMiddleware([ValidateCsrfToken::class, PreventRequestForgery::class]);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->client->forceFill([
        'client_id' => 'my-app',
        'grant_types' => ['authorization_code', 'refresh_token', TestCase::TOKEN_EXCHANGE_GRANT],
        'allowed_exchange_audiences' => ['https://api.internal/orders'],
    ])->save();
});

it('issues, introspects and revokes under the wire client_id while storing the key', function (): void {
    $sink = fakeAudit();
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $this->actingAsIdentity($this->user, authTime: time() - 60)->withSession(['oidc.sid' => $sid]);

    $result = $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid');
    $result->response->assertOk();

    $accessToken = parseAccessToken((string) $result->accessToken);
    $record = AccessToken::query()->find($accessToken->claims()->get('jti'));

    expect($accessToken->claims()->get('client_id'))->toBe('my-app')
        ->and($accessToken->claims()->get('aud'))->toBe([app(IssuerResolver::class)->url()])
        ->and(parseIdToken((string) $result->idToken)->claims()->get('aud'))->toBe(['my-app'])
        ->and($record->client_id)->toBe((string) $this->client->getKey())
        ->and(app(OidcSessionRepository::class)->participantClientIds($sid))->toBe([(string) $this->client->getKey()]);

    $sink->assertRecorded(TokenIssued::TYPE, fn (AuditRecord $record): bool => $record->clientId === 'my-app');

    $this->postJson('/oauth/introspect', [
        'client_id' => 'my-app',
        'client_secret' => $this->client->plainSecret,
        'token' => $result->accessToken,
    ])->assertOk()->assertJsonPath('active', true)->assertJsonPath('client_id', 'my-app');

    $this->postJson('/oauth/introspect', [
        'client_id' => 'my-app',
        'client_secret' => $this->client->plainSecret,
        'token' => $result->refreshToken,
        'token_type_hint' => 'refresh_token',
    ])->assertOk()->assertJsonPath('active', true)->assertJsonPath('client_id', 'my-app');

    $this->postJson('/oauth/revoke', [
        'client_id' => 'my-app',
        'client_secret' => $this->client->plainSecret,
        'token' => $result->accessToken,
    ])->assertOk();

    expect($record->refresh()->revoked)->toBeTrue();
    $sink->assertRecorded(TokenRevoked::TYPE, fn (AuditRecord $record): bool => $record->clientId === 'my-app');
});

it('exchanges a token issued under the wire client_id and names it in the act claim', function (): void {
    config(['oidc.scopes' => ['openid' => 'Authenticate', 'orders:read' => 'Read orders']]);
    $subject = mintExchangeSubjectToken('my-app', (string) $this->user->id, ['openid', 'orders:read']);

    $response = $this->post('/oauth/token', [
        'grant_type' => TestCase::TOKEN_EXCHANGE_GRANT,
        'client_id' => 'my-app',
        'client_secret' => $this->client->plainSecret,
        'subject_token' => $subject,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        'audience' => 'https://api.internal/orders',
        'scope' => 'orders:read',
    ])->assertOk();

    expect(parseAccessToken((string) $response->json('access_token'))->claims()->get('act'))->toBe(['client_id' => 'my-app']);
});

it('addresses the back-channel logout token to the wire client_id', function (): void {
    Queue::fake();
    $this->client->forceFill(['backchannel_logout_uri' => 'https://rp.test/backchannel'])->save();
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $this->actingAsIdentity($this->user, authTime: time() - 60)->withSession(['oidc.sid' => $sid]);

    $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid')->response->assertOk();
    app(OidcSessionRepository::class)->revoke($sid);
    app(BackChannelLogoutNotifier::class)->notify($sid);

    Queue::assertPushed(SendBackChannelLogout::class, fn (SendBackChannelLogout $job): bool => $job->clientKey === (string) $this->client->getKey());
});

it('trusts a client configured by its wire client_id', function (): void {
    config(['oidc.clients.trusted' => ['my-app']]);

    $response = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get('/oauth/authorize?'.http_build_query([
            'client_id' => 'my-app',
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'st4te',
            'code_challenge' => $this->pkce()->challenge,
            'code_challenge_method' => 'S256',
        ]));

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toStartWith('https://rp.test/callback?')->toContain('code=');
});
