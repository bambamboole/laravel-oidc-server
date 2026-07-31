<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorRegistry;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Workbench\App\Models\User;

it('configures native passkey routes from package auth settings', function () {
    expect(route('identity.passkey.login-options'))->toEndWith('/auth/passkeys/login/options')
        ->and(route('identity.passkey.confirm'))->toEndWith('/auth/passkeys/confirm')
        ->and(config('passkeys.guard'))->toBe(config('oidc.auth.guard'))
        ->and(config('passkeys.redirect'))->toBe(config('oidc.auth.home'));
});

it('does not register the vendor passkey registration routes', function () {
    expect(Route::has('identity.passkey.registration-options'))->toBeFalse()
        ->and(Route::has('identity.passkey.store'))->toBeFalse()
        ->and(Route::has('identity.passkey.destroy'))->toBeFalse();
});

it('exposes passkeys as webauthn factor enrollments', function () {
    expect(class_implements(User::class))->toHaveKey('Laravel\\Passkeys\\Contracts\\PasskeyUser')
        ->and(app(FactorRegistry::class)->get('webauthn')->key())->toBe('webauthn');
});

it('challenges a password login with an enrolled passkey by default', function () {
    $user = User::create([
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => Hash::make('password'),
    ]);

    $user->passkeys()->create([
        'name' => 'Security key',
        'credential_id' => 'credential-id',
        'credential' => [],
    ]);

    $this->post(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'password',
    ])->assertRedirect(route('identity.two-factor.login', absolute: false));

    expect(session('login.factor'))->toBe('webauthn');
    $this->assertGuest('identity');
});

it('does not force the deferred WebAuthn MFA ceremony when webauthn is not a challenge provider', function () {
    config(['oidc.auth.two_factor.challenge_providers' => ['totp']]);

    $user = User::create([
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => Hash::make('password'),
    ]);

    $user->passkeys()->create([
        'name' => 'Security key',
        'credential_id' => 'credential-id',
        'credential' => [],
    ]);

    $this->post(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'password',
    ])->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user, 'identity');
});
