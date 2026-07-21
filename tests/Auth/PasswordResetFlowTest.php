<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Facades\Oidc;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Workbench\App\Models\User;

function resolvePasswordBroker(): PasswordBroker
{
    $broker = app('auth.password.broker');

    if (! $broker instanceof PasswordBroker) {
        throw new RuntimeException('The configured password broker is not a concrete password broker.');
    }

    return $broker;
}

it('sends a password reset link through the Laravel broker', function () {
    Notification::fake();

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);

    $this->from('/auth/forgot-password')
        ->post(route('identity.password.email'), ['email' => 'm@example.com'])
        ->assertRedirect('/auth/forgot-password')
        ->assertSessionHas('status', __(Password::RESET_LINK_SENT));

    Notification::assertSentTo(
        $user,
        ResetPassword::class,
        fn (ResetPassword $notification): bool => str_contains(
            (string) $notification->toMail($user)->actionUrl,
            '/auth/reset-password/',
        ),
    );
});

it('resets a password through the package action seam and logs the user in', function () {
    Event::fake([PasswordReset::class]);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = resolvePasswordBroker()->createToken($user);

    Oidc::resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->post(route('identity.password.update'), [
        'token' => $token,
        'email' => 'm@example.com',
        'password' => 'new-password',
        'password_confirmation' => 'new-password',
    ])->assertRedirect(route('identity.login'));

    $this->assertAuthenticatedAs($user->fresh(), 'identity');
    expect(Hash::check('new-password', (string) User::query()->findOrFail($user->getKey())->getAttribute('password')))->toBeTrue();
    Event::assertDispatched(PasswordReset::class);
});

it('returns validation errors for an invalid reset token', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);

    Oidc::resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->from('/auth/reset-password/invalid-token')
        ->post(route('identity.password.update'), [
            'token' => 'invalid-token',
            'email' => (string) $user->getAttribute('email'),
            'password' => 'new-password',
            'password_confirmation' => 'new-password',
        ])
        ->assertRedirect('/auth/reset-password/invalid-token')
        ->assertSessionHasErrors('email');
});
