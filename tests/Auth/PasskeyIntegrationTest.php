<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorRegistry;
use Illuminate\Support\Facades\Hash;
use Workbench\App\Models\User;

it('configures native passkey routes from package auth settings', function () {
    expect(route('identity.passkey.login-options'))->toEndWith('/auth/passkeys/login/options')
        ->and(route('identity.passkey.store'))->toEndWith('/auth/user/passkeys')
        ->and(config('passkeys.guard'))->toBe(config('oidc.auth.guard'))
        ->and(config('passkeys.redirect'))->toBe(config('oidc.auth.home'));
});

it('exposes passkeys as webauthn factor enrollments', function () {
    expect(class_implements(User::class))->toHaveKey('Laravel\\Passkeys\\Contracts\\PasskeyUser')
        ->and(app(FactorRegistry::class)->get('webauthn')->key())->toBe('webauthn');
});

it('does not force the deferred WebAuthn MFA ceremony during password login', function () {
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
