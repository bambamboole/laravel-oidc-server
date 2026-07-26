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
        ->and(DB::table('oidc_totp_factors')->value('secret'))->not->toBe($factor->secret);

    managementRequest($this, $user)->getJson(route('identity.two-factor.qr-code'))
        ->assertOk()
        ->assertJsonStructure(['svg', 'url']);

    managementRequest($this, $user)->getJson(route('identity.two-factor.secret-key'))
        ->assertOk()
        ->assertJson(['secretKey' => $factor->secret]);

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

    $originalCodes = managementRequest($this, $user)
        ->getJson(route('identity.two-factor.recovery-codes'))
        ->assertOk()
        ->json();

    expect($originalCodes)->toHaveCount(8);

    managementRequest($this, $user)
        ->postJson(route('identity.two-factor.regenerate-recovery-codes'))
        ->assertOk();

    $newCodes = managementRequest($this, $user)->getJson(route('identity.two-factor.recovery-codes'))->json();

    expect($newCodes)->toHaveCount(8)->not->toBe($originalCodes);

    managementRequest($this, $user)
        ->deleteJson(route('identity.two-factor.revoke', ['provider' => 'totp', 'enrollment' => $enrollment['id']]))
        ->assertNoContent();

    expect($user->totpFactors()->count())->toBe(0)
        ->and($user->recoveryCodes()->count())->toBe(0);
});

it('returns 404 from all two-factor read endpoints when 2FA is not enabled', function () {
    $user = managementUser();

    managementRequest($this, $user)
        ->getJson(route('identity.two-factor.qr-code'))
        ->assertNotFound();

    managementRequest($this, $user)
        ->getJson(route('identity.two-factor.secret-key'))
        ->assertNotFound();

    managementRequest($this, $user)
        ->getJson(route('identity.two-factor.recovery-codes'))
        ->assertNotFound();
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
