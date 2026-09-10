<?php

declare(strict_types=1);

/**
 * Password reset through the Laravel broker and the ResetUserPassword action seam, finalizing as a login
 */

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;
use Workbench\App\Models\User;

function resolvePasswordBroker(): PasswordBroker
{
    $broker = app('auth.password.broker');

    if (! $broker instanceof PasswordBroker) {
        throw new RuntimeException('The configured password broker is not a concrete password broker.');
    }

    return $broker;
}

it('sends a password reset link through the Laravel broker', function (): void {
    Notification::fake();

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);

    $this->from('/realms/default/auth/forgot-password')
        ->post(route('identity.password.email'), ['email' => 'm@example.com'])
        ->assertRedirect('/realms/default/auth/forgot-password')
        ->assertSessionHas('status', __(Password::RESET_LINK_SENT));

    Notification::assertSentTo(
        $user,
        ResetPassword::class,
        fn (ResetPassword $notification): bool => str_contains(
            (string) $notification->toMail($user)->actionUrl,
            '/realms/default/auth/reset-password/',
        ),
    );
});

it('resets a password through the package action seam and logs the user in', function (): void {
    Event::fake([PasswordReset::class]);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = resolvePasswordBroker()->createToken($user);

    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
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

// `confirmed` is enforced by the request itself, ahead of the broker and the app's reset action.
it('rejects a mismatched or missing password confirmation before reaching the reset action', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = resolvePasswordBroker()->createToken($user);
    $actionRan = false;

    resetUserPasswordsUsing(function (CanResetPassword $user, array $input) use (&$actionRan): void {
        $actionRan = true;

        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->from('/realms/default/auth/reset-password/'.$token)
        ->post(route('identity.password.update'), [
            'token' => $token,
            'email' => 'm@example.com',
            'password' => 'new-password',
            'password_confirmation' => 'a-different-password',
        ])
        ->assertRedirect('/realms/default/auth/reset-password/'.$token)
        ->assertSessionHasErrors('password');

    $this->postJson(route('identity.password.update'), [
        'token' => $token,
        'email' => 'm@example.com',
        'password' => 'new-password',
    ])->assertStatus(422)->assertJsonValidationErrors('password');

    $this->assertGuest('identity');
    expect($actionRan)->toBeFalse()
        ->and(Hash::check('old-password', (string) User::query()->findOrFail($user->getKey())->getAttribute('password')))->toBeTrue();
});

// Rules beyond `confirmed` belong to the app's reset action; its ValidationException must surface, not 500.
it('surfaces a validation error the reset action raises for its own password rules', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = resolvePasswordBroker()->createToken($user);

    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        Validator::make($input, ['password' => ['min:20']])->validate();

        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->from('/realms/default/auth/reset-password/'.$token)
        ->post(route('identity.password.update'), [
            'token' => $token,
            'email' => 'm@example.com',
            'password' => 'too-short',
            'password_confirmation' => 'too-short',
        ])
        ->assertRedirect('/realms/default/auth/reset-password/'.$token)
        ->assertSessionHasErrors('password');

    $this->assertGuest('identity');
    expect(Hash::check('old-password', (string) User::query()->findOrFail($user->getKey())->getAttribute('password')))->toBeTrue();
});

it('returns validation errors for an invalid reset token', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);

    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->from('/realms/default/auth/reset-password/invalid-token')
        ->post(route('identity.password.update'), [
            'token' => 'invalid-token',
            'email' => (string) $user->getAttribute('email'),
            'password' => 'new-password',
            'password_confirmation' => 'new-password',
        ])
        ->assertRedirect('/realms/default/auth/reset-password/invalid-token')
        ->assertSessionHasErrors('email');
});
