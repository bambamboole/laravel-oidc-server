<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
});

function purgeTokenFixture(string $id, bool $revoked, ?string $expiresAt, string $userId, string $clientId): AccessToken
{
    $token = new AccessToken;
    $token->forceFill([
        'id' => $id,
        'user_id' => $userId,
        'client_id' => $clientId,
        'scopes' => ['openid'],
        'revoked' => $revoked,
        'expires_at' => $expiresAt,
    ])->save();

    return $token;
}

it('keeps live tokens and removes revoked and long-expired ones', function () {
    purgeTokenFixture('live', false, now()->addHour()->toDateTimeString(), (string) $this->user->id, (string) $this->client->id);
    purgeTokenFixture('revoked', true, now()->addHour()->toDateTimeString(), (string) $this->user->id, (string) $this->client->id);
    purgeTokenFixture('expired', false, now()->subWeeks(2)->toDateTimeString(), (string) $this->user->id, (string) $this->client->id);

    $this->artisan('oidc:purge')->assertSuccessful();

    expect(AccessToken::query()->pluck('id')->all())->toBe(['live']);
});

it('keeps records that expired inside the retention window', function () {
    purgeTokenFixture('recently-expired', false, now()->subHour()->toDateTimeString(), (string) $this->user->id, (string) $this->client->id);

    $this->artisan('oidc:purge')->assertSuccessful();

    expect(AccessToken::query()->whereKey('recently-expired')->exists())->toBeTrue();
});

it('purges only revoked records when asked', function () {
    purgeTokenFixture('revoked', true, now()->addHour()->toDateTimeString(), (string) $this->user->id, (string) $this->client->id);
    purgeTokenFixture('expired', false, now()->subWeeks(2)->toDateTimeString(), (string) $this->user->id, (string) $this->client->id);

    $this->artisan('oidc:purge', ['--revoked' => true])->assertSuccessful();

    expect(AccessToken::query()->pluck('id')->all())->toBe(['expired']);
});

it('purges refresh tokens and authorization codes too', function () {
    purgeTokenFixture('access', false, now()->subWeeks(2)->toDateTimeString(), (string) $this->user->id, (string) $this->client->id);

    (new RefreshToken)->forceFill([
        'id' => 'refresh',
        'access_token_id' => 'access',
        'revoked' => false,
        'expires_at' => now()->subWeeks(2)->toDateTimeString(),
    ])->save();

    (new AuthorizationCode)->forceFill([
        'id' => 'code',
        'user_id' => $this->user->id,
        'client_id' => $this->client->id,
        'scopes' => ['openid'],
        'code_challenge' => str_repeat('c', 43),
        'code_challenge_method' => 'S256',
        'revoked' => true,
        'expires_at' => now()->addHour()->toDateTimeString(),
    ])->save();

    $this->artisan('oidc:purge')->assertSuccessful();

    expect(AccessToken::query()->count())->toBe(0)
        ->and(RefreshToken::query()->count())->toBe(0)
        ->and(AuthorizationCode::query()->count())->toBe(0);
});
