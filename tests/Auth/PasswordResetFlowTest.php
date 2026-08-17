<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Facades\Oidc;
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

/**
 * `confirmed` is enforced by the request itself, ahead of the broker — the reset
 * page ships a confirmation field, so a typo must not commit the first value.
 * The action is registered but has to stay untouched: rejection happens before
 * any user is looked up or written.
 */
it('rejects a mismatched password confirmation before reaching the reset action', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = resolvePasswordBroker()->createToken($user);
    $actionRan = false;

    Oidc::resetUserPasswordsUsing(function (CanResetPassword $user, array $input) use (&$actionRan): void {
        $actionRan = true;

        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->from('/auth/reset-password/'.$token)
        ->post(route('identity.password.update'), [
            'token' => $token,
            'email' => 'm@example.com',
            'password' => 'new-password',
            'password_confirmation' => 'a-different-password',
        ])
        ->assertRedirect('/auth/reset-password/'.$token)
        ->assertSessionHasErrors('password');

    $this->assertGuest('identity');
    expect($actionRan)->toBeFalse()
        ->and(Hash::check('old-password', (string) User::query()->findOrFail($user->getKey())->getAttribute('password')))->toBeTrue();
});

it('rejects a reset request with no password confirmation at all', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = resolvePasswordBroker()->createToken($user);

    Oidc::resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->postJson(route('identity.password.update'), [
        'token' => $token,
        'email' => 'm@example.com',
        'password' => 'new-password',
    ])->assertStatus(422)->assertJsonValidationErrors('password');

    expect(Hash::check('old-password', (string) User::query()->findOrFail($user->getKey())->getAttribute('password')))->toBeTrue();
});

/**
 * Every rule beyond `confirmed` belongs to the app's reset action. What the
 * package owns is the seam: a ValidationException thrown inside the broker's
 * reset callback has to surface as a validation error rather than a 500, and
 * must not leave a half-applied reset behind.
 */
it('surfaces a validation error the reset action raises for its own password rules', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = resolvePasswordBroker()->createToken($user);

    Oidc::resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        Validator::make($input, ['password' => ['min:20']])->validate();

        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->from('/auth/reset-password/'.$token)
        ->post(route('identity.password.update'), [
            'token' => $token,
            'email' => 'm@example.com',
            'password' => 'too-short',
            'password_confirmation' => 'too-short',
        ])
        ->assertRedirect('/auth/reset-password/'.$token)
        ->assertSessionHasErrors('password');

    $this->assertGuest('identity');
    expect(Hash::check('old-password', (string) User::query()->findOrFail($user->getKey())->getAttribute('password')))->toBeTrue();
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
