<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Authentication\Models\PasswordResetToken;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\Models\SessionParticipant;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Carbon\CarbonInterface;
use Workbench\App\Models\User;

beforeEach(function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
});

function prunedAccessToken(mixed $test, string $id, ?CarbonInterface $revokedAt, CarbonInterface $expiresAt): void
{
    (new AccessToken)->forceFill([
        'id' => $id,
        'realm_id' => AccessToken::currentRealm(),
        'user_id' => (string) $test->user->id,
        'client_id' => (string) $test->client->id,
        'scopes' => ['openid'],
        'revoked_at' => $revokedAt,
        'expires_at' => $expiresAt,
    ])->save();
}

function prunedSession(CarbonInterface $expiresAt, ?CarbonInterface $notifiedAt): string
{
    $repository = app(OidcSessionRepository::class);
    $sid = $repository->start((string) User::factory()->create()->getKey());

    OidcSession::query()->whereKey($sid)->update(['expires_at' => $expiresAt, 'logout_notified_at' => $notifiedAt]);
    $repository->recordParticipant($sid, (string) Client::factory()->create()->getKey());

    return $sid;
}

it('keeps a token until both its revocation and its expiry are past the retention window', function (): void {
    prunedAccessToken($this, 'live', null, now()->addHour());
    prunedAccessToken($this, 'recently-expired', null, now()->subHour());
    prunedAccessToken($this, 'recently-revoked', now()->subHour(), now()->addHour());
    prunedAccessToken($this, 'long-expired', null, now()->subWeeks(2));
    prunedAccessToken($this, 'long-revoked', now()->subWeeks(2), now()->addHour());

    $this->artisan('oidc:prune')->assertSuccessful();

    expect(AccessToken::query()->pluck('id')->all())
        ->toEqualCanonicalizing(['live', 'recently-expired', 'recently-revoked']);
});

it('prunes refresh tokens and authorization codes on the same rule', function (): void {
    prunedAccessToken($this, 'access', null, now()->subWeeks(2));

    (new RefreshToken)->forceFill([
        'id' => 'refresh',
        'realm_id' => RefreshToken::currentRealm(),
        'access_token_id' => 'access',
        'expires_at' => now()->subWeeks(2),
    ])->save();

    (new AuthorizationCode)->forceFill([
        'code' => str_repeat('c', 80),
        'realm_id' => AuthorizationCode::currentRealm(),
        'user_id' => $this->user->id,
        'client_id' => $this->client->id,
        'scopes' => ['openid'],
        'code_challenge' => str_repeat('c', 43),
        'code_challenge_method' => 'S256',
        'revoked_at' => now()->subWeeks(2),
        'expires_at' => now()->addHour(),
    ])->save();

    $this->artisan('oidc:prune')->assertSuccessful();

    expect(AccessToken::query()->count())->toBe(0)
        ->and(RefreshToken::query()->count())->toBe(0)
        ->and(AuthorizationCode::query()->count())->toBe(0);
});

it('prunes a session only once both its expiry and its logout notification are past the grace window', function (): void {
    $unnotified = prunedSession(now()->subDays(2), null);
    $recentlyNotified = prunedSession(now()->subDays(2), now());
    $notified = prunedSession(now()->subDays(2), now()->subDays(2));
    $live = prunedSession(now()->subMinute(), now()->subMinute());

    $this->artisan('oidc:prune')->assertSuccessful();

    expect(OidcSession::query()->pluck('id')->all())
        ->toEqualCanonicalizing([$unnotified, $recentlyNotified, $live])
        ->and(SessionParticipant::query()->where('session_id', $notified)->exists())->toBeFalse()
        ->and(SessionParticipant::query()->where('session_id', $unnotified)->exists())->toBeTrue();
});

it('prunes expired authentication contexts', function (): void {
    $live = pruneTestContext(now()->addDay());
    pruneTestContext(now()->subDay());

    $this->artisan('oidc:prune')->assertSuccessful();

    expect(AuthenticationContext::query()->pluck('id')->all())->toBe([$live->id]);
});

it('prunes password reset links past the window they were valid for', function (): void {
    $ttl = (int) config('oidc.tokens.password_reset');

    $live = PasswordResetToken::factory()->create(['created_at' => now()->subSeconds($ttl - 60)]);
    PasswordResetToken::factory()->create(['created_at' => now()->subSeconds($ttl + 60)]);

    $this->artisan('oidc:prune')->assertSuccessful();

    expect(PasswordResetToken::query()->pluck('id')->all())->toBe([$live->id]);
});

function pruneTestContext(CarbonInterface $expiresAt): AuthenticationContext
{
    $context = new AuthenticationContext;
    $context->realm_id = AuthenticationContext::currentRealm();
    $context->user_id = (string) User::factory()->create()->getKey();
    $context->amr = ['pwd'];
    $context->acr = '1';
    $context->auth_time = time();
    $context->id_token_claims = [];
    $context->access_token_claims = [];
    $context->expires_at = $expiresAt;
    $context->created_at = now();
    $context->save();

    return $context;
}
