<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\RecoveryCodeProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\TotpFactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\LoginApi;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Server\Facades\Oidc;
use Bambamboole\LaravelOidc\Server\Routing\Handler;
use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\Hash;
use PragmaRX\Google2FA\Google2FA;
use Workbench\App\Models\User;

function auditTestUser(): User
{
    return User::create(['name' => 'M', 'email' => 'audit@example.com', 'password' => Hash::make('password')]);
}

it('audits a successful password login with sid and amr', function () {
    $sink = fakeAudit();
    $user = auditTestUser();

    $this->post(route(Handler::LoginStore->value), ['email' => 'audit@example.com', 'password' => 'password']);

    $event = $sink->assertRecorded(AuditEventType::LoginSucceeded);

    expect($event->userId)->toBe((string) $user->getAuthIdentifier())
        ->and($event->sid)->not->toBeNull()
        ->and($event->context['amr'])->toBe(['pwd'])
        ->and($event->ip)->not->toBeNull();
});

it('audits a login attempt with invalid credentials', function () {
    $sink = fakeAudit();
    auditTestUser();

    $this->post(route(Handler::LoginStore->value), ['email' => 'audit@example.com', 'password' => 'wrong']);

    $sink->assertRecorded(AuditEventType::LoginFailed, fn (AuditEvent $event): bool => $event->context['reason'] === 'invalid_credentials'
        && $event->context['username'] === 'audit@example.com'
        && $event->context['method'] === 'pwd');
    $sink->assertNotRecorded(AuditEventType::LoginSucceeded);
});

it('audits a login denied by the postLogin policy', function () {
    $sink = fakeAudit();
    auditTestUser();
    Oidc::postLogin(fn (LoginEvent $event, LoginApi $api) => $api->deny('blocked'));

    $this->post(route(Handler::LoginStore->value), ['email' => 'audit@example.com', 'password' => 'password']);

    $sink->assertRecorded(AuditEventType::LoginFailed, fn (AuditEvent $event): bool => $event->context['reason'] === 'policy_denied'
        && $event->context['deny_reason'] === 'blocked');
    $sink->assertNotRecorded(AuditEventType::LoginSucceeded);
});

it('audits a full mfa challenge round trip', function () {
    $sink = fakeAudit();
    $user = auditTestUser();
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    $this->post(route(Handler::LoginStore->value), ['email' => 'audit@example.com', 'password' => 'password'])
        ->assertRedirect(route(Handler::TwoFactorLogin->value));

    $sink->assertNotRecorded(AuditEventType::LoginSucceeded);

    $this->post(route(Handler::TwoFactorLoginStore->value), ['code' => '000000'])
        ->assertSessionHasErrors('code');

    $sink->assertRecorded(AuditEventType::MfaChallengeFailed, fn (AuditEvent $event): bool => $event->context['factor'] === 'totp'
        && $event->context['reason'] === 'invalid_code'
        && $event->userId === (string) $user->getAuthIdentifier());

    $code = app(Google2FA::class)->getCurrentOtp($factor->secret);

    $this->post(route(Handler::TwoFactorLoginStore->value), ['code' => $code])
        ->assertRedirect('/dashboard');

    $sink->assertRecorded(AuditEventType::MfaChallengeSucceeded, fn (AuditEvent $event): bool => $event->context['factor'] === 'totp');
    $sink->assertRecorded(AuditEventType::LoginSucceeded, fn (AuditEvent $event): bool => $event->context['amr'] === ['pwd', 'otp']);
    $sink->assertNotRecorded(AuditEventType::RecoveryCodeUsed);
});

it('audits a recovery code login', function () {
    $sink = fakeAudit();
    $user = auditTestUser();
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();
    app(RecoveryCodeProvider::class)->generate($user);
    $recoveryCode = $user->recoveryCodes()->firstOrFail()->code;

    $this->withSession(['login.id' => $user->getAuthIdentifier(), 'login.factor' => 'totp'])
        ->post(route(Handler::TwoFactorLoginStore->value), ['recovery_code' => $recoveryCode])
        ->assertRedirect('/dashboard');

    $sink->assertRecorded(AuditEventType::RecoveryCodeUsed, fn (AuditEvent $event): bool => $event->userId === (string) $user->getAuthIdentifier());
    $sink->assertRecorded(AuditEventType::MfaChallengeSucceeded, fn (AuditEvent $event): bool => $event->context['factor'] === 'recovery_code');
});

it('audits the factor enrollment lifecycle', function () {
    $sink = fakeAudit();
    $user = auditTestUser();
    $session = ['auth.password_confirmed_at' => time()];

    $enrollment = $this->actingAs($user, 'identity')->withSession($session)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->json();

    $sink->assertRecorded(AuditEventType::FactorEnrollmentStarted, fn (AuditEvent $event): bool => $event->context['factor'] === 'totp'
        && $event->context['enrollment_id'] === $enrollment['id']);

    $code = app(Google2FA::class)->getCurrentOtp($enrollment['metadata']['secret']);

    $this->actingAs($user, 'identity')->withSession($session)
        ->postJson(route(Handler::TwoFactorEnrollConfirm->value, ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => $code,
        ])->assertOk();

    $sink->assertRecorded(AuditEventType::FactorConfirmed, fn (AuditEvent $event): bool => $event->context['factor'] === 'totp');

    $this->actingAs($user, 'identity')->withSession($session)
        ->deleteJson(route(Handler::TwoFactorRevoke->value, ['provider' => 'totp', 'enrollment' => $enrollment['id']]))
        ->assertNoContent();

    $sink->assertRecorded(AuditEventType::FactorRevoked, fn (AuditEvent $event): bool => $event->context['factor'] === 'totp'
        && $event->context['enrollment_id'] === $enrollment['id']);
});

it('audits a registration', function () {
    $sink = fakeAudit();
    Oidc::createUsersUsing(fn (array $input): Authenticatable => User::create([
        'name' => $input['name'],
        'email' => $input['email'],
        'password' => Hash::make($input['password']),
    ]));

    $this->post(route(Handler::RegisterStore->value), [
        'name' => 'M',
        'email' => 'audit@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ])->assertRedirect('/dashboard');

    $user = User::where('email', 'audit@example.com')->firstOrFail();

    $sink->assertRecorded(AuditEventType::UserRegistered, fn (AuditEvent $event): bool => $event->userId === (string) $user->getAuthIdentifier());
    $sink->assertRecorded(AuditEventType::LoginSucceeded);
});

it('audits a password reset', function () {
    $sink = fakeAudit();
    $user = auditTestUser();
    $broker = app('auth.password.broker');

    if (! $broker instanceof PasswordBroker) {
        throw new RuntimeException('The configured password broker is not a concrete password broker.');
    }

    $token = $broker->createToken($user);
    Oidc::resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->post(route(Handler::PasswordUpdate->value), [
        'token' => $token,
        'email' => 'audit@example.com',
        'password' => 'new-password',
        'password_confirmation' => 'new-password',
    ]);

    $sink->assertRecorded(AuditEventType::PasswordReset, fn (AuditEvent $event): bool => $event->userId === (string) $user->getAuthIdentifier());
});

it('audits a logout with the sid still attached', function () {
    $sink = fakeAudit();
    $user = auditTestUser();

    $this->post(route(Handler::LoginStore->value), ['email' => 'audit@example.com', 'password' => 'password']);

    $this->post(route(Handler::Logout->value));

    $event = $sink->assertRecorded(AuditEventType::Logout);

    expect($event->userId)->toBe((string) $user->getAuthIdentifier())
        ->and($event->sid)->not->toBeNull();
});
