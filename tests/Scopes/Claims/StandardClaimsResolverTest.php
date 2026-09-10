<?php

declare(strict_types=1);

/**
 * OpenID Connect Core 1.0 §5.1 (standard claims), §5.1.1 (address), §5.4 (scope → claims mapping)
 */

use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsRequest;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\StandardClaimsResolver;
use Bambamboole\LaravelOidc\Server\Scopes\Enums\ClaimsAudience;
use Illuminate\Contracts\Auth\Authenticatable;
use Workbench\App\Models\User;

/**
 * @param  list<string>  $scopes
 * @return array<string, mixed>
 */
function standardClaims(Authenticatable $user, array $scopes): array
{
    return (new StandardClaimsResolver)->resolve(new ClaimsRequest(
        user: $user,
        audience: ClaimsAudience::IdToken,
        clientId: 'client-uuid',
        scopes: $scopes,
    ));
}

it('maps the profile and email scopes onto the user attributes', function (): void {
    $user = User::create(['name' => 'Manuel', 'email' => 'manuel@example.com', 'email_verified_at' => now(), 'password' => 'secret']);
    $user->forceFill(['locale' => 'de', 'timezone' => 'Europe/Berlin']);

    $profile = standardClaims($user, ['profile']);

    expect($profile)->toHaveKey('name', 'Manuel')
        ->and($profile)->toHaveKey('updated_at')
        ->and($profile)->toHaveKey('locale', 'de')
        ->and($profile)->toHaveKey('zoneinfo', 'Europe/Berlin')
        ->and(standardClaims($user, ['email']))->toBe(['email' => 'manuel@example.com', 'email_verified' => true])
        ->and(standardClaims($user, ['openid']))->toBe([]);
});

it('reports an unverified email and omits attributes the user does not carry', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    expect(standardClaims($user, ['email']))->toBe(['email' => 'm@example.com', 'email_verified' => false])
        ->and(array_keys(standardClaims($user, ['profile'])))->not->toContain('locale', 'zoneinfo')
        ->and(standardClaims($user, ['phone', 'address']))->toBe([]);
});

// OIDC Core §5.4 — phone scope
it('maps phone_number and phone_number_verified under the phone scope', function (): void {
    $verified = (new User)->forceFill(['phone_number' => '+49 30 123456', 'phone_number_verified' => 1]);
    $unverified = (new User)->forceFill(['phone_number' => '+49 30 123456']);

    expect(standardClaims($verified, ['phone']))->toBe(['phone_number' => '+49 30 123456', 'phone_number_verified' => true])
        ->and(standardClaims($unverified, ['phone']))->toBe(['phone_number' => '+49 30 123456']);
});

// OIDC Core §5.1.1 — the structured address claim
it('maps a structured or plain-string address under the address scope, keeping the standard members only', function (): void {
    $structured = (new User)->forceFill(['address' => [
        'street_address' => 'Unter den Linden 1',
        'locality' => 'Berlin',
        'postal_code' => '10117',
        'country' => 'DE',
        'internal_id' => 'ignored',
    ]]);
    $plain = (new User)->forceFill(['address' => "Unter den Linden 1\n10117 Berlin"]);

    expect(standardClaims($structured, ['address']))->toBe(['address' => [
        'street_address' => 'Unter den Linden 1',
        'locality' => 'Berlin',
        'postal_code' => '10117',
        'country' => 'DE',
    ]])
        ->and(standardClaims($plain, ['address']))->toBe(['address' => ['formatted' => "Unter den Linden 1\n10117 Berlin"]]);
});
