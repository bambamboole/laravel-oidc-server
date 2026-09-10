<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Events\LoggedOut;
use Bambamboole\LaravelOidc\Server\Authentication\Events\LoginFailed;
use Bambamboole\LaravelOidc\Server\Authentication\Events\LoginSucceeded;
use Bambamboole\LaravelOidc\Server\Authentication\Events\PasswordReset;
use Bambamboole\LaravelOidc\Server\Authentication\Events\UserRegistered;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginApi;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Server\Credentials\Events\FactorConfirmed;
use Bambamboole\LaravelOidc\Server\Credentials\Events\FactorEnrollmentStarted;
use Bambamboole\LaravelOidc\Server\Credentials\Events\FactorRevoked;
use Bambamboole\LaravelOidc\Server\Credentials\Events\MfaChallengeFailed;
use Bambamboole\LaravelOidc\Server\Credentials\Events\MfaChallengeSucceeded;
use Bambamboole\LaravelOidc\Server\Credentials\Events\RecoveryCodeUsed;
use Bambamboole\LaravelOidc\Server\Credentials\RecoveryCodeProvider;
use Bambamboole\LaravelOidc\Server\Credentials\TotpFactorProvider;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;
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

it('audits a successful password login with sid and amr', function (): void {
    $sink = fakeAudit();
    $user = auditTestUser();

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password']);

    $record = $sink->assertRecorded(LoginSucceeded::TYPE);

    expect($record->userId)->toBe((string) $user->getAuthIdentifier())
        ->and($record->sid)->not->toBeNull()
        ->and($record->context['amr'])->toBe(['pwd'])
        ->and($record->ip)->not->toBeNull();
});

it('audits a login attempt with invalid credentials', function (): void {
    $sink = fakeAudit();
    auditTestUser();

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'wrong']);

    $sink->assertRecorded(LoginFailed::TYPE, fn (AuditRecord $record): bool => $record->context['reason'] === 'invalid_credentials'
        && $record->context['username'] === 'audit@example.com'
        && $record->context['method'] === 'pwd');
    $sink->assertNotRecorded(LoginSucceeded::TYPE);
});

it('audits a login denied by the postLogin policy', function (): void {
    $sink = fakeAudit();
    auditTestUser();
    app(PostLoginPipeline::class)->register(fn (LoginEvent $event, LoginApi $api) => $api->deny('blocked'));

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password']);

    $sink->assertRecorded(LoginFailed::TYPE, fn (AuditRecord $record): bool => $record->context['reason'] === 'policy_denied'
        && $record->context['deny_reason'] === 'blocked');
    $sink->assertNotRecorded(LoginSucceeded::TYPE);
});

it('audits a full mfa challenge round trip', function (): void {
    $sink = fakeAudit();
    $user = auditTestUser();
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password'])
        ->assertRedirect(route('identity.two-factor.login'));

    $sink->assertNotRecorded(LoginSucceeded::TYPE);

    $this->post(route('identity.two-factor.login.store'), ['code' => '000000'])
        ->assertSessionHasErrors('code');

    $sink->assertRecorded(MfaChallengeFailed::TYPE, fn (AuditRecord $record): bool => $record->context['factor'] === 'totp'
        && $record->context['reason'] === 'invalid_code'
        && $record->userId === (string) $user->getAuthIdentifier());

    $code = app(Google2FA::class)->getCurrentOtp($factor->secret);

    $this->post(route('identity.two-factor.login.store'), ['code' => $code])
        ->assertRedirect('/dashboard');

    $sink->assertRecorded(MfaChallengeSucceeded::TYPE, fn (AuditRecord $record): bool => $record->context['factor'] === 'totp');
    $sink->assertRecorded(LoginSucceeded::TYPE, fn (AuditRecord $record): bool => $record->context['amr'] === ['pwd', 'otp']);
    $sink->assertNotRecorded(RecoveryCodeUsed::TYPE);
});

it('audits a recovery code login', function (): void {
    $sink = fakeAudit();
    $user = auditTestUser();
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();
    app(RecoveryCodeProvider::class)->generate($user);
    $recoveryCode = $user->recoveryCodes()->firstOrFail()->code;

    $this->withSession(['login.id' => $user->getAuthIdentifier(), 'login.factor' => 'totp'])
        ->post(route('identity.two-factor.login.store'), ['recovery_code' => $recoveryCode])
        ->assertRedirect('/dashboard');

    $sink->assertRecorded(RecoveryCodeUsed::TYPE, fn (AuditRecord $record): bool => $record->userId === (string) $user->getAuthIdentifier());
    $sink->assertRecorded(MfaChallengeSucceeded::TYPE, fn (AuditRecord $record): bool => $record->context['factor'] === 'recovery_code');
});

it('audits the factor enrollment lifecycle', function (): void {
    $sink = fakeAudit();
    $user = auditTestUser();
    $session = ['auth.password_confirmed_at' => time()];

    $enrollment = $this->actingAs($user, 'identity')->withSession($session)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))
        ->json();

    $sink->assertRecorded(FactorEnrollmentStarted::TYPE, fn (AuditRecord $record): bool => $record->context['factor'] === 'totp'
        && $record->context['enrollment_id'] === $enrollment['id']);

    $code = app(Google2FA::class)->getCurrentOtp($enrollment['metadata']['secret']);

    $this->actingAs($user, 'identity')->withSession($session)
        ->postJson(route('identity.two-factor.enroll.confirm', ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => $code,
        ])->assertOk();

    $sink->assertRecorded(FactorConfirmed::TYPE, fn (AuditRecord $record): bool => $record->context['factor'] === 'totp');

    $this->actingAs($user, 'identity')->withSession($session)
        ->deleteJson(route('identity.two-factor.revoke', ['provider' => 'totp', 'enrollment' => $enrollment['id']]))
        ->assertNoContent();

    $sink->assertRecorded(FactorRevoked::TYPE, fn (AuditRecord $record): bool => $record->context['factor'] === 'totp'
        && $record->context['enrollment_id'] === $enrollment['id']);
});

it('audits a registration', function (): void {
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

    $sink->assertRecorded(UserRegistered::TYPE, fn (AuditRecord $record): bool => $record->userId === (string) $user->getAuthIdentifier());
    $sink->assertRecorded(LoginSucceeded::TYPE);
});

it('audits a password reset', function (): void {
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

    $sink->assertRecorded(PasswordReset::TYPE, fn (AuditRecord $record): bool => $record->userId === (string) $user->getAuthIdentifier());
});

it('audits a logout with the sid still attached', function (): void {
    $sink = fakeAudit();
    $user = auditTestUser();

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password']);

    $this->post(route('oidc.logout'));

    $record = $sink->assertRecorded(LoggedOut::TYPE);

    expect($record->userId)->toBe((string) $user->getAuthIdentifier())
        ->and($record->sid)->not->toBeNull();
});
