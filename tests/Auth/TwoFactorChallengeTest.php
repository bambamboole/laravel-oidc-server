<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\MultiFactor\Models\TotpFactor;
use Bambamboole\LaravelOidc\Auth\MultiFactor\TwoFactorManager;
use Bambamboole\LaravelOidc\Facades\Oidc;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use PragmaRX\Google2FA\Google2FA;
use Workbench\App\Models\User;

/**
 * @return array{User, TotpFactor}
 */
function confirmedTotpUser(): array
{
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    $factor = app(TwoFactorManager::class)->enable($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    return [$user, $factor];
}

it('renders the two-factor challenge through the package view seam', function () {
    Oidc::twoFactorChallengeView(fn (Request $request) => response('two-factor-view'));
    [$user] = confirmedTotpUser();

    $this->withSession(['login.id' => $user->getAuthIdentifier()])
        ->get(route('identity.two-factor.login'))
        ->assertOk()
        ->assertSee('two-factor-view');
});

it('defers guard login until a confirmed factor is verified', function () {
    [$user, $factor] = confirmedTotpUser();

    $this->post(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'password',
        'remember' => true,
    ])->assertRedirect(route('identity.two-factor.login'))
        ->assertSessionHas('login.id', $user->getAuthIdentifier())
        ->assertSessionHas('login.remember', true);

    $this->assertGuest('identity');

    $code = app(Google2FA::class)->getCurrentOtp($factor->secret);

    $this->post(route('identity.two-factor.login.store'), ['code' => $code])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user, 'identity');
});

it('returns the Fortify-compatible JSON challenge response', function () {
    [$user] = confirmedTotpUser();

    $this->postJson(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'password',
    ])->assertOk()->assertJson(['two_factor' => true]);

    $this->assertGuest('identity');
});

it('rejects invalid and replayed TOTP codes', function () {
    [$user, $factor] = confirmedTotpUser();

    $this->withSession(['login.id' => $user->getAuthIdentifier()])
        ->post(route('identity.two-factor.login.store'), ['code' => '000000'])
        ->assertSessionHasErrors('code');

    $code = app(Google2FA::class)->getCurrentOtp($factor->secret);

    $this->withSession(['login.id' => $user->getAuthIdentifier()])
        ->post(route('identity.two-factor.login.store'), ['code' => $code])
        ->assertRedirect('/dashboard');

    auth('identity')->logout();

    $this->withSession(['login.id' => $user->getAuthIdentifier()])
        ->post(route('identity.two-factor.login.store'), ['code' => $code])
        ->assertSessionHasErrors('code');
});

it('consumes one recovery code and logs the challenged user in', function () {
    [$user] = confirmedTotpUser();
    $recoveryCode = $user->recoveryCodes()->firstOrFail()->code;

    $this->withSession(['login.id' => $user->getAuthIdentifier()])
        ->post(route('identity.two-factor.login.store'), ['recovery_code' => $recoveryCode])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user, 'identity');
    expect($user->recoveryCodes()->whereNull('used_at')->count())->toBe(7);

    auth('identity')->logout();

    $this->withSession(['login.id' => $user->getAuthIdentifier()])
        ->post(route('identity.two-factor.login.store'), ['recovery_code' => $recoveryCode])
        ->assertSessionHasErrors('recovery_code');
});

it('appends the otp method after a successful totp challenge', function () {
    [$user, $factor] = confirmedTotpUser();

    $code = app(Google2FA::class)->getCurrentOtp($factor->secret);

    $this->withSession(['login.id' => $user->getAuthIdentifier(), 'oidc.amr' => ['pwd']])
        ->post(route('identity.two-factor.login.store'), ['code' => $code])
        ->assertRedirect('/dashboard');

    expect(session()->get('oidc.amr'))->toBe(['pwd', 'otp']);
});

it('appends the otp method after a successful recovery code challenge', function () {
    [$user] = confirmedTotpUser();
    $recoveryCode = $user->recoveryCodes()->firstOrFail()->code;

    $this->withSession(['login.id' => $user->getAuthIdentifier(), 'oidc.amr' => ['pwd']])
        ->post(route('identity.two-factor.login.store'), ['recovery_code' => $recoveryCode])
        ->assertRedirect('/dashboard');

    expect(session()->get('oidc.amr'))->toBe(['pwd', 'otp']);
});

it('redirects challenge requests without a pending user to login', function () {
    $this->get(route('identity.two-factor.login'))->assertRedirect(route('identity.login'));
});

it('throttles repeated two-factor challenge attempts', function () {
    [$user] = confirmedTotpUser();

    foreach (range(1, 5) as $ignored) {
        $this->withSession(['login.id' => $user->getAuthIdentifier()])
            ->post(route('identity.two-factor.login.store'), ['code' => '000000']);
    }

    $this->withSession(['login.id' => $user->getAuthIdentifier()])
        ->post(route('identity.two-factor.login.store'), ['code' => '000000'])
        ->assertStatus(429);
});
