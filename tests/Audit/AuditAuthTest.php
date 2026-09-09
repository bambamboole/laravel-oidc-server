<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginApi;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Server\Credentials\RecoveryCodeProvider;
use Bambamboole\LaravelOidc\Server\Credentials\TotpFactorProvider;
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

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password']);

    $event = $sink->assertRecorded(AuditEventType::LoginSucceeded);

    expect($event->userId)->toBe((string) $user->getAuthIdentifier())
        ->and($event->sid)->not->toBeNull()
        ->and($event->context['amr'])->toBe(['pwd'])
        ->and($event->ip)->not->toBeNull();
});

it('audits a login attempt with invalid credentials', function () {
    $sink = fakeAudit();
    auditTestUser();

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'wrong']);

    $sink->assertRecorded(AuditEventType::LoginFailed, fn (AuditEvent $event): bool => $event->context['reason'] === 'invalid_credentials'
        && $event->context['username'] === 'audit@example.com'
        && $event->context['method'] === 'pwd');
    $sink->assertNotRecorded(AuditEventType::LoginSucceeded);
});

it('audits a login denied by the postLogin policy', function () {
    $sink = fakeAudit();
    auditTestUser();
    app(PostLoginPipeline::class)->register(fn (LoginEvent $event, LoginApi $api) => $api->deny('blocked'));

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password']);

    $sink->assertRecorded(AuditEventType::LoginFailed, fn (AuditEvent $event): bool => $event->context['reason'] === 'policy_denied'
        && $event->context['deny_reason'] === 'blocked');
    $sink->assertNotRecorded(AuditEventType::LoginSucceeded);
});

it('audits a full mfa challenge round trip', function () {
    $sink = fakeAudit();
    $user = auditTestUser();
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password'])
        ->assertRedirect(route('identity.two-factor.login'));

    $sink->assertNotRecorded(AuditEventType::LoginSucceeded);

    $this->post(route('identity.two-factor.login.store'), ['code' => '000000'])
        ->assertSessionHasErrors('code');

    $sink->assertRecorded(AuditEventType::MfaChallengeFailed, fn (AuditEvent $event): bool => $event->context['factor'] === 'totp'
        && $event->context['reason'] === 'invalid_code'
        && $event->userId === (string) $user->getAuthIdentifier());

    $code = app(Google2FA::class)->getCurrentOtp($factor->secret);

    $this->post(route('identity.two-factor.login.store'), ['code' => $code])
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
        ->post(route('identity.two-factor.login.store'), ['recovery_code' => $recoveryCode])
        ->assertRedirect('/dashboard');

    $sink->assertRecorded(AuditEventType::RecoveryCodeUsed, fn (AuditEvent $event): bool => $event->userId === (string) $user->getAuthIdentifier());
    $sink->assertRecorded(AuditEventType::MfaChallengeSucceeded, fn (AuditEvent $event): bool => $event->context['factor'] === 'recovery_code');
});

it('audits the factor enrollment lifecycle', function () {
    $sink = fakeAudit();
    $user = auditTestUser();
    $session = ['auth.password_confirmed_at' => time()];

    $enrollment = $this->actingAs($user, 'identity')->withSession($session)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))
        ->json();

    $sink->assertRecorded(AuditEventType::FactorEnrollmentStarted, fn (AuditEvent $event): bool => $event->context['factor'] === 'totp'
        && $event->context['enrollment_id'] === $enrollment['id']);

    $code = app(Google2FA::class)->getCurrentOtp($enrollment['metadata']['secret']);

    $this->actingAs($user, 'identity')->withSession($session)
        ->postJson(route('identity.two-factor.enroll.confirm', ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => $code,
        ])->assertOk();

    $sink->assertRecorded(AuditEventType::FactorConfirmed, fn (AuditEvent $event): bool => $event->context['factor'] === 'totp');

    $this->actingAs($user, 'identity')->withSession($session)
        ->deleteJson(route('identity.two-factor.revoke', ['provider' => 'totp', 'enrollment' => $enrollment['id']]))
        ->assertNoContent();

    $sink->assertRecorded(AuditEventType::FactorRevoked, fn (AuditEvent $event): bool => $event->context['factor'] === 'totp'
        && $event->context['enrollment_id'] === $enrollment['id']);
});

it('audits a registration', function () {
    $sink = fakeAudit();
    createUsersUsing(fn (array $input): Authenticatable => User::create([
        'name' => $input['name'],
        'email' => $input['email'],
        'password' => Hash::make($input['password']),
    ]));

    $this->post(route('identity.register.store'), [
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
    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->post(route('identity.password.update'), [
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

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password']);

    $this->post(route('oidc.logout'));

    $event = $sink->assertRecorded(AuditEventType::Logout);

    expect($event->userId)->toBe((string) $user->getAuthIdentifier())
        ->and($event->sid)->not->toBeNull();
});
