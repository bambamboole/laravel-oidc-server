<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Workbench\App\Models\User;

beforeEach(function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
});

function purgeTokenFixture(mixed $test, string $id, bool $revoked, string $expiresAt): AccessToken
{
    $token = new AccessToken;
    $token->forceFill([
        'id' => $id,
        'realm_id' => AccessToken::currentRealm(),
        'user_id' => (string) $test->user->id,
        'client_id' => (string) $test->client->id,
        'scopes' => ['openid'],
        'revoked_at' => $revoked ? now() : null,
        'expires_at' => $expiresAt,
    ])->save();

    return $token;
}

it('keeps live and recently expired tokens and removes revoked and long-expired ones', function (): void {
    purgeTokenFixture($this, 'live', false, now()->addHour()->toDateTimeString());
    purgeTokenFixture($this, 'recently-expired', false, now()->subHour()->toDateTimeString());
    purgeTokenFixture($this, 'revoked', true, now()->addHour()->toDateTimeString());
    purgeTokenFixture($this, 'expired', false, now()->subWeeks(2)->toDateTimeString());

    $this->artisan('oidc:purge')->assertSuccessful();

    expect(AccessToken::query()->pluck('id')->all())->toEqualCanonicalizing(['live', 'recently-expired']);
});

it('purges only revoked records when asked', function (): void {
    purgeTokenFixture($this, 'revoked', true, now()->addHour()->toDateTimeString());
    purgeTokenFixture($this, 'expired', false, now()->subWeeks(2)->toDateTimeString());

    $this->artisan('oidc:purge', ['--revoked' => true])->assertSuccessful();

    expect(AccessToken::query()->pluck('id')->all())->toBe(['expired']);
});

it('purges refresh tokens and authorization codes too', function (): void {
    purgeTokenFixture($this, 'access', false, now()->subWeeks(2)->toDateTimeString());

    (new RefreshToken)->forceFill([
        'id' => 'refresh',
        'realm_id' => RefreshToken::currentRealm(),
        'access_token_id' => 'access',
        'expires_at' => now()->subWeeks(2)->toDateTimeString(),
    ])->save();

    (new AuthorizationCode)->forceFill([
        'code' => str_repeat('c', 80),
        'realm_id' => AuthorizationCode::currentRealm(),
        'user_id' => $this->user->id,
        'client_id' => $this->client->id,
        'scopes' => ['openid'],
        'code_challenge' => str_repeat('c', 43),
        'code_challenge_method' => 'S256',
        'revoked_at' => now(),
        'expires_at' => now()->addHour()->toDateTimeString(),
    ])->save();

    $this->artisan('oidc:purge')->assertSuccessful();

    expect(AccessToken::query()->count())->toBe(0)
        ->and(RefreshToken::query()->count())->toBe(0)
        ->and(AuthorizationCode::query()->count())->toBe(0);
});
