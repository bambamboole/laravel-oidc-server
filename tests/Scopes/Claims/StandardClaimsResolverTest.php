<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsAudience;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsRequest;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsResolver;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\StandardClaimsResolver;
use Illuminate\Contracts\Auth\Authenticatable;
use Workbench\App\Models\User;

/**
 * @param  list<string>  $scopes
 * @return array<string, mixed>
 */
function defaultResolverClaims(Authenticatable $user, array $scopes): array
{
    return (new StandardClaimsResolver)->resolve(new ClaimsRequest(
        user: $user,
        audience: ClaimsAudience::IdToken,
        clientId: 'client-uuid',
        scopes: $scopes,
    ));
}

it('is bound as the default claims resolver', function () {
    expect(app(ClaimsResolver::class)::class)->toBe(StandardClaimsResolver::class);
});

it('maps common user attributes into scope-grouped claims', function () {
    $user = User::create([
        'name' => 'Manuel',
        'email' => 'manuel@example.com',
        'email_verified_at' => now(),
        'password' => 'secret',
    ]);

    expect(defaultResolverClaims($user, ['profile']))->toHaveKey('name', 'Manuel')
        ->and(defaultResolverClaims($user, ['profile']))->toHaveKey('updated_at')
        ->and(defaultResolverClaims($user, ['email']))->toBe(['email' => 'manuel@example.com', 'email_verified' => true])
        ->and(defaultResolverClaims($user, ['profile', 'email']))->toHaveKeys(['name', 'email']);
});

it('returns no claims for scopes without claims', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    expect(defaultResolverClaims($user, ['openid']))->toBe([]);
});

it('marks email unverified when email_verified_at is null', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    expect(defaultResolverClaims($user, ['email']))
        ->toBe(['email' => 'm@example.com', 'email_verified' => false]);
});

it('maps locale and timezone attributes when present', function () {
    $user = (new User)->forceFill([
        'name' => 'Manuel',
        'locale' => 'de',
        'timezone' => 'Europe/Berlin',
    ]);

    $claims = defaultResolverClaims($user, ['profile']);

    expect($claims)->toHaveKey('locale', 'de')
        ->and($claims)->toHaveKey('zoneinfo', 'Europe/Berlin');
});

it('omits locale and zoneinfo for users without those attributes', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $claims = defaultResolverClaims($user, ['profile']);

    expect(array_keys($claims))->not->toContain('locale')
        ->and(array_keys($claims))->not->toContain('zoneinfo');
});
