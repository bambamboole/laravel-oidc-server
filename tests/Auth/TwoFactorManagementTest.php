<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Models\TotpFactor;
use Illuminate\Support\Facades\DB;
use PragmaRX\Google2FA\Google2FA;
use Workbench\App\Models\User;

function managementUser(): User
{
    return User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
}

function managementRequest(mixed $test, User $user): mixed
{
    return $test->actingAs($user, 'identity')->withSession(['auth.password_confirmed_at' => time()]);
}

it('enrolls and confirms a TOTP factor through the provider-keyed routes', function () {
    $user = managementUser();

    $enrollment = managementRequest($this, $user)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))
        ->assertCreated()
        ->json();

    $factor = TotpFactor::query()->firstOrFail();

    expect($factor->authenticatable->is($user))->toBeTrue()
        ->and($factor->confirmed_at)->toBeNull()
        ->and($enrollment['metadata']['secret'])->toBe($factor->secret)
        ->and($enrollment['metadata']['qr_svg'])->toContain('<svg')
        ->and($enrollment['metadata']['qr_url'])->toContain('otpauth://')
        ->and(DB::table('oidc_totp_factors')->value('secret'))->not->toBe($factor->secret);

    $code = app(Google2FA::class)->getCurrentOtp($factor->secret);

    managementRequest($this, $user)
        ->postJson(route('identity.two-factor.enroll.confirm', ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => $code,
        ])->assertOk();

    expect($factor->refresh()->confirmed_at)->not->toBeNull()
        ->and($user->recoveryCodes()->count())->toBe(8);
});

it('lists regenerates and revokes recovery credentials', function () {
    $user = managementUser();

    $enrollment = managementRequest($this, $user)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))
        ->json();

    $code = app(Google2FA::class)->getCurrentOtp($enrollment['metadata']['secret']);

    managementRequest($this, $user)
        ->postJson(route('identity.two-factor.enroll.confirm', ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => $code,
        ])->assertOk();

    // Recovery codes were backfilled on confirmation; re-enrolling the
    // recovery_code provider regenerates them and is the only place the
    // plaintext codes appear.
    expect($user->recoveryCodes()->count())->toBe(8);

    $originalCodes = $user->recoveryCodes()->pluck('code')->all();

    $regenerated = managementRequest($this, $user)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'recovery_code']))
        ->assertCreated()
        ->json();

    expect($regenerated['metadata']['codes'])->toHaveCount(8)->not->toBe($originalCodes);

    $listing = managementRequest($this, $user)
        ->getJson(route('identity.two-factor.factors'))
        ->assertOk()
        ->json('factors');

    $recoveryRows = array_values(array_filter($listing, fn (array $row): bool => $row['provider'] === 'recovery_code'));

    expect($recoveryRows)->toHaveCount(1)
        ->and($recoveryRows[0]['metadata'])->toBe([]);

    managementRequest($this, $user)
        ->deleteJson(route('identity.two-factor.revoke', ['provider' => 'totp', 'enrollment' => $enrollment['id']]))
        ->assertNoContent();

    expect($user->totpFactors()->count())->toBe(0)
        ->and($user->recoveryCodes()->count())->toBe(0);
});

it('allows multiple TOTP enrollments per user', function () {
    $user = managementUser();

    $user->totpFactors()->createMany([
        ['name' => 'Phone', 'secret' => 'FIRSTSECRET'],
        ['name' => 'Tablet', 'secret' => 'SECONDSECRET'],
    ]);

    expect($user->totpFactors)->toHaveCount(2);
});

it('requires recent password confirmation to manage factors', function () {
    $user = managementUser();

    $this->actingAs($user, 'identity')
        ->post(route('identity.two-factor.enroll', ['provider' => 'totp']))
        ->assertRedirect(route('identity.password.confirm'));

    expect($user->totpFactors()->exists())->toBeFalse();
});

it('removes provider-owned factors when the authenticatable is deleted', function () {
    $user = managementUser();

    $enrollment = managementRequest($this, $user)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))
        ->json();

    $code = app(Google2FA::class)->getCurrentOtp($enrollment['metadata']['secret']);

    managementRequest($this, $user)
        ->postJson(route('identity.two-factor.enroll.confirm', ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => $code,
        ])->assertOk();

    $user->delete();

    expect(DB::table('oidc_totp_factors')->count())->toBe(0)
        ->and(DB::table('oidc_recovery_codes')->count())->toBe(0);
});
