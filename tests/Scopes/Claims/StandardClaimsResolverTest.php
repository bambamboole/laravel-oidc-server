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

// OIDC Core §5.4 — phone scope
it('maps phone_number and phone_number_verified under the phone scope', function () {
    $user = (new User)->forceFill(['phone_number' => '+49 30 123456', 'phone_number_verified' => 1]);

    expect(defaultResolverClaims($user, ['phone']))->toBe(['phone_number' => '+49 30 123456', 'phone_number_verified' => true]);
});

it('omits phone_number_verified when the user carries no verification attribute', function () {
    $user = (new User)->forceFill(['phone_number' => '+49 30 123456']);

    expect(defaultResolverClaims($user, ['phone']))->toBe(['phone_number' => '+49 30 123456']);
});

// OIDC Core §5.1.1 — the structured address claim
it('maps a structured address under the address scope, keeping the standard members only', function () {
    $user = (new User)->forceFill(['address' => [
        'street_address' => 'Unter den Linden 1',
        'locality' => 'Berlin',
        'postal_code' => '10117',
        'country' => 'DE',
        'internal_id' => 'ignored',
    ]]);

    expect(defaultResolverClaims($user, ['address']))->toBe(['address' => [
        'street_address' => 'Unter den Linden 1',
        'locality' => 'Berlin',
        'postal_code' => '10117',
        'country' => 'DE',
    ]]);
});

it('maps a plain string address as the formatted member', function () {
    $user = (new User)->forceFill(['address' => "Unter den Linden 1\n10117 Berlin"]);

    expect(defaultResolverClaims($user, ['address']))->toBe(['address' => ['formatted' => "Unter den Linden 1\n10117 Berlin"]]);
});

it('emits nothing for the phone and address scopes when the user has no such attributes', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    expect(defaultResolverClaims($user, ['phone', 'address']))->toBe([]);
});

it('omits locale and zoneinfo for users without those attributes', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    $claims = defaultResolverClaims($user, ['profile']);

    expect(array_keys($claims))->not->toContain('locale')
        ->and(array_keys($claims))->not->toContain('zoneinfo');
});
