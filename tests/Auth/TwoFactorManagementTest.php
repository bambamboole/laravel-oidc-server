<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\MultiFactor\Models\TotpFactor;
use Illuminate\Support\Facades\DB;
use PragmaRX\Google2FA\Google2FA;
use Workbench\App\Models\User;

it('enables and confirms a TOTP factor through Fortify-compatible routes', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time()])
        ->postJson(route('identity.two-factor.enable'))
        ->assertOk();

    $factor = TotpFactor::query()->firstOrFail();

    expect($factor->authenticatable->is($user))->toBeTrue()
        ->and($factor->confirmed_at)->toBeNull()
        ->and($user->recoveryCodes()->count())->toBe(8)
        ->and(DB::table('oidc_totp_factors')->value('secret'))->not->toBe($factor->secret);

    $this->actingAs($user, 'identity')->getJson(route('identity.two-factor.qr-code'))
        ->assertOk()
        ->assertJsonStructure(['svg', 'url']);

    $this->actingAs($user, 'identity')->getJson(route('identity.two-factor.secret-key'))
        ->assertOk()
        ->assertJson(['secretKey' => $factor->secret]);

    $code = app(Google2FA::class)->getCurrentOtp($factor->secret);

    $this->actingAs($user, 'identity')
        ->postJson(route('identity.two-factor.confirm'), ['code' => $code])
        ->assertOk();

    expect($factor->refresh()->confirmed_at)->not->toBeNull();
});

it('lists regenerates and disables recovery credentials', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time()])
        ->postJson(route('identity.two-factor.enable'))
        ->assertOk();

    $originalCodes = $this->actingAs($user, 'identity')
        ->getJson(route('identity.two-factor.recovery-codes'))
        ->assertOk()
        ->json();

    expect($originalCodes)->toHaveCount(8);

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time()])
        ->postJson(route('identity.two-factor.regenerate-recovery-codes'))
        ->assertOk();

    $newCodes = $this->actingAs($user, 'identity')->getJson(route('identity.two-factor.recovery-codes'))->json();

    expect($newCodes)->toHaveCount(8)->not->toBe($originalCodes);

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time()])
        ->deleteJson(route('identity.two-factor.disable'))
        ->assertOk();

    expect($user->totpFactors()->count())->toBe(0)
        ->and($user->recoveryCodes()->count())->toBe(0);
});

it('allows multiple TOTP enrollments per user', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $user->totpFactors()->createMany([
        ['name' => 'Phone', 'secret' => 'FIRSTSECRET'],
        ['name' => 'Tablet', 'secret' => 'SECONDSECRET'],
    ]);

    expect($user->totpFactors)->toHaveCount(2);
});

it('requires recent password confirmation to manage factors', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')
        ->post(route('identity.two-factor.enable'))
        ->assertRedirect(route('identity.password.confirm'));

    expect($user->totpFactors()->exists())->toBeFalse();
});

it('removes provider-owned factors when the authenticatable is deleted', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time()])
        ->postJson(route('identity.two-factor.enable'))
        ->assertOk();

    $user->delete();

    expect(DB::table('oidc_totp_factors')->count())->toBe(0)
        ->and(DB::table('oidc_recovery_codes')->count())->toBe(0);
});
