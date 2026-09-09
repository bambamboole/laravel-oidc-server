<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Tokens\Context\AccessTokenContext;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
});

function purgeTokenFixture(string $id, bool $revoked, ?string $expiresAt, string $userId, string $clientId): Token
{
    $token = new Token;
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

    expect(Token::query()->pluck('id')->all())->toBe(['live']);
});

it('keeps records that expired inside the retention window', function () {
    purgeTokenFixture('recently-expired', false, now()->subHour()->toDateTimeString(), (string) $this->user->id, (string) $this->client->id);

    $this->artisan('oidc:purge')->assertSuccessful();

    expect(Token::query()->whereKey('recently-expired')->exists())->toBeTrue();
});

it('purges only revoked records when asked', function () {
    purgeTokenFixture('revoked', true, now()->addHour()->toDateTimeString(), (string) $this->user->id, (string) $this->client->id);
    purgeTokenFixture('expired', false, now()->subWeeks(2)->toDateTimeString(), (string) $this->user->id, (string) $this->client->id);

    $this->artisan('oidc:purge', ['--revoked' => true])->assertSuccessful();

    expect(Token::query()->pluck('id')->all())->toBe(['expired']);
});

it('purges refresh tokens and authorization codes too', function () {
    purgeTokenFixture('access', false, now()->subWeeks(2)->toDateTimeString(), (string) $this->user->id, (string) $this->client->id);

    (new RefreshToken)->forceFill([
        'id' => 'refresh',
        'access_token_id' => 'access',
        'revoked' => false,
        'expires_at' => now()->subWeeks(2)->toDateTimeString(),
    ])->save();

    (new AuthCode)->forceFill([
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

    expect(Token::query()->count())->toBe(0)
        ->and(RefreshToken::query()->count())->toBe(0)
        ->and(AuthCode::query()->count())->toBe(0);
});

it('prunes access-token context links beyond the session-plus-refresh retention horizon', function () {
    $stale = new AccessTokenContext;
    $stale->access_token_id = 'stale';
    $stale->context_id = 'ctx';
    $stale->created_at = now()->subDays(400);
    $stale->save();

    $fresh = new AccessTokenContext;
    $fresh->access_token_id = 'fresh';
    $fresh->context_id = 'ctx';
    $fresh->created_at = now();
    $fresh->save();

    $this->artisan('oidc:purge')->assertSuccessful();

    expect(AccessTokenContext::query()->where('access_token_id', 'stale')->exists())->toBeFalse()
        ->and(AccessTokenContext::query()->where('access_token_id', 'fresh')->exists())->toBeTrue();
});
