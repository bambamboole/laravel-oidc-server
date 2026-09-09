<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Actions\ResetPassword;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Workbench\App\Models\User;

it('resets the password through the bound action and audits it', function () {
    Event::fake([PasswordReset::class]);
    $audit = fakeAudit();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $result = app(ResetPassword::class)([
        'email' => 'm@example.com',
        'token' => Password::createToken($user),
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ]);

    expect($result->succeeded())->toBeTrue()
        ->and($result->status)->toBe(Password::PASSWORD_RESET)
        ->and(Hash::check('new-password-123', (string) $user->fresh()?->getAuthPassword()))->toBeTrue();
    Event::assertDispatched(PasswordReset::class);
    $audit->assertRecorded(AuditEventType::PasswordReset);
});

it('reports the broker status without a user for an invalid token', function () {
    $audit = fakeAudit();
    resetUserPasswordsUsing(fn () => throw new LogicException('must not run'));
    User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);

    $result = app(ResetPassword::class)([
        'email' => 'm@example.com',
        'token' => 'not-a-token',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ]);

    expect($result->succeeded())->toBeFalse()
        ->and($result->status)->toBe(Password::INVALID_TOKEN);
    $audit->assertNotRecorded(AuditEventType::PasswordReset);
});
