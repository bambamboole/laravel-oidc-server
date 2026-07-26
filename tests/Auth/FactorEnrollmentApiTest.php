<?php

declare(strict_types=1);

/**
 * Provider-keyed factor enrollment: any registered EnrollableFactorProvider
 * gets enroll/confirm/revoke endpoints and appears in the factor listing, so
 * new factor types need no package changes.
 */

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Models\TotpFactor;
use Bambamboole\LaravelOidc\Server\Routing\Handler;
use Illuminate\Support\Facades\Hash;
use PragmaRX\Google2FA\Google2FA;
use Workbench\App\Models\User;

function enrollmentUser(): User
{
    return User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
}

function actingAsEnrollmentUser(mixed $test, User $user): mixed
{
    return $test->actingAs($user, 'identity')->withSession(['auth.password_confirmed_at' => time()]);
}

it('lists enrollments across all providers', function () {
    $user = enrollmentUser();
    $user->totpFactors()->create(['name' => 'Authenticator app', 'secret' => 'SECRET', 'confirmed_at' => now()]);
    $user->passkeys()->create(['name' => 'My key', 'credential_id' => 'AQIDBA', 'credential' => ['type' => 'public-key']]);

    actingAsEnrollmentUser($this, $user)
        ->getJson(route(Handler::TwoFactorFactors->value))
        ->assertOk()
        ->assertJsonFragment(['provider' => 'totp'])
        ->assertJsonFragment(['provider' => 'webauthn']);
});

it('enrolls a factor through its provider key', function () {
    $user = enrollmentUser();

    $response = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->assertCreated();

    expect($response->json('provider'))->toBe('totp')
        ->and($response->json('metadata.secret'))->toBeString();

    $factor = $user->totpFactors()->latest('id')->first();
    expect($factor)->not->toBeNull()
        ->and($factor->confirmed_at)->toBeNull();
});

it('confirms an enrollment and backfills recovery codes', function () {
    $user = enrollmentUser();

    $enrollment = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->json();

    $code = app(Google2FA::class)->getCurrentOtp($enrollment['metadata']['secret']);

    actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnrollConfirm->value, ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => $code,
        ])->assertOk();

    expect($user->totpFactors()->whereNotNull('confirmed_at')->exists())->toBeTrue()
        ->and($user->recoveryCodes()->count())->toBeGreaterThan(0);
});

it('returns the existing pending enrollment instead of stacking rows', function () {
    $user = enrollmentUser();

    $first = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->json();

    $second = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->assertCreated()
        ->json();

    expect($user->totpFactors()->count())->toBe(1)
        ->and($second['id'])->toBe($first['id'])
        ->and($second['metadata']['secret'])->toBe($first['metadata']['secret']);
});

it('begins a fresh pending enrollment alongside a confirmed factor', function () {
    $user = enrollmentUser();
    $confirmed = $user->totpFactors()->create(['name' => 'Authenticator app', 'secret' => 'SECRET']);
    $confirmed->forceFill(['confirmed_at' => now()])->save();

    $enrollment = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->assertCreated()
        ->json();

    expect($user->totpFactors()->count())->toBe(2)
        ->and($enrollment['id'])->not->toBe((string) $confirmed->getKey())
        ->and($confirmed->refresh()->confirmed_at)->not->toBeNull();
});

it('rejects an enrollment confirmation with an invalid code', function () {
    $user = enrollmentUser();

    $enrollment = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->json();

    actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnrollConfirm->value, ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => '000000',
        ])->assertUnprocessable();

    expect($user->totpFactors()->whereNotNull('confirmed_at')->exists())->toBeFalse();
});

it('revokes an enrollment', function () {
    $user = enrollmentUser();
    $factor = $user->totpFactors()->create(['name' => 'Authenticator app', 'secret' => 'SECRET', 'confirmed_at' => now()]);

    actingAsEnrollmentUser($this, $user)
        ->deleteJson(route(Handler::TwoFactorRevoke->value, ['provider' => 'totp', 'enrollment' => $factor->getKey()]))
        ->assertNoContent();

    expect(TotpFactor::query()->whereKey($factor->getKey())->exists())->toBeFalse();
});

it('returns 404 for an unknown or non-enrollable provider', function () {
    $user = enrollmentUser();

    actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'sms']))
        ->assertNotFound();

    // WebAuthn enrolls through the passkey ceremony routes, not this surface.
    actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'webauthn']))
        ->assertNotFound();
});

it('requires authentication', function () {
    $this->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))->assertUnauthorized();
});
