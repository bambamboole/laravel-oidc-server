<?php

declare(strict_types=1);

/**
 * Every interactive login path — password, social, registration, password
 * reset, passkey — must finalize through the shared post-login sequence, so
 * the postLogin policy and amr tracking apply uniformly.
 */

use Bambamboole\LaravelOidc\Auth\AuthenticationMethods;
use Bambamboole\LaravelOidc\Auth\MultiFactor\TwoFactorManager;
use Bambamboole\LaravelOidc\Auth\Pipeline\LoginApi;
use Bambamboole\LaravelOidc\Auth\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Facades\Oidc;
use Bambamboole\LaravelOidc\Routing\Handler;
use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\Hash;
use Illuminate\Testing\TestResponse;
use Laravel\Passkeys\Actions\VerifyPasskey;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Passkey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Workbench\App\Models\User;

function finalizationPasswordToken(User $user): string
{
    $broker = app('auth.password.broker');

    if (! $broker instanceof PasswordBroker) {
        throw new RuntimeException('The configured password broker is not a concrete password broker.');
    }

    return $broker->createToken($user);
}

function finalizationRegisterUsers(): void
{
    Oidc::createUsersUsing(fn (array $input): Authenticatable => User::create([
        'name' => $input['name'],
        'email' => $input['email'],
        'password' => Hash::make($input['password']),
    ]));
}

/**
 * @return TestResponse<Response>
 */
function finalizationPasskeyLogin(mixed $test, User $user): TestResponse
{
    $passkey = $user->passkeys()->create([
        'name' => 'Key',
        'credential_id' => 'cred-'.uniqid(),
        'credential' => ['type' => 'public-key'],
    ]);

    app()->instance(VerifyPasskey::class, new class($passkey) extends VerifyPasskey
    {
        public function __construct(private readonly Passkey $result) {}

        public function __invoke(
            PublicKeyCredential $credential,
            PublicKeyCredentialRequestOptions $options,
            ?PasskeyUser $user = null,
        ): Passkey {
            return $this->result;
        }
    });

    $authenticatorData = Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32)."\x01".pack('N', 1));
    $clientDataJson = Base64UrlSafe::encodeUnpadded((string) json_encode([
        'type' => 'webauthn.get', 'challenge' => 'AQIDBA', 'origin' => 'http://localhost',
    ]));

    return $test->withSession([
        'passkey.verification_options' => (string) json_encode(['challenge' => 'AQIDBA', 'rpId' => 'localhost', 'timeout' => 60000]),
    ])->post(route(Handler::PasskeyLogin->value), [
        'credential' => [
            'id' => 'AQIDBA',
            'rawId' => 'AQIDBA',
            'type' => 'public-key',
            'authenticatorAttachment' => null,
            'response' => [
                'clientDataJSON' => $clientDataJson,
                'authenticatorData' => $authenticatorData,
                'signature' => 'AQIDBA',
                'userHandle' => null,
            ],
        ],
    ]);
}

it('applies the postLogin policy to registration', function () {
    finalizationRegisterUsers();
    Oidc::postLogin(fn (LoginEvent $e, LoginApi $api) => $api->deny('blocked'));

    $this->post(route(Handler::RegisterStore->value), [
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ]);

    expect(User::where('email', 'm@example.com')->exists())->toBeTrue();
    $this->assertGuest('identity');
});

it('records amr for registration logins', function () {
    finalizationRegisterUsers();

    $this->post(route(Handler::RegisterStore->value), [
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ])->assertRedirect('/dashboard');

    expect(session(AuthenticationMethods::SESSION_KEY))->toContain('pwd');
});

it('applies the postLogin policy to password resets', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = finalizationPasswordToken($user);

    Oidc::resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });
    Oidc::postLogin(fn (LoginEvent $e, LoginApi $api) => $api->deny('blocked'));

    $this->post(route(Handler::PasswordUpdate->value), [
        'token' => $token,
        'email' => 'm@example.com',
        'password' => 'new-password',
        'password_confirmation' => 'new-password',
    ]);

    expect(Hash::check('new-password', (string) $user->fresh()->getAttribute('password')))->toBeTrue();
    $this->assertGuest('identity');
});

it('records amr for password-reset logins', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = finalizationPasswordToken($user);

    Oidc::resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->post(route(Handler::PasswordUpdate->value), [
        'token' => $token,
        'email' => 'm@example.com',
        'password' => 'new-password',
        'password_confirmation' => 'new-password',
    ]);

    $this->assertAuthenticatedAs($user->fresh(), 'identity');
    expect(session(AuthenticationMethods::SESSION_KEY))->toContain('pwd');
});

it('applies the postLogin policy to passkey logins', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    Oidc::postLogin(fn (LoginEvent $e, LoginApi $api) => $api->deny('blocked'));

    finalizationPasskeyLogin($this, $user)->assertSessionHasErrors();

    $this->assertGuest('identity');
});

it('records amr swk for passkey logins', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    finalizationPasskeyLogin($this, $user);

    $this->assertAuthenticatedAs($user, 'identity');
    expect(session(AuthenticationMethods::SESSION_KEY))->toContain('swk');
});

it('does not challenge an enrolled second factor after a passkey login', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    $factor = app(TwoFactorManager::class)->enable($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    finalizationPasskeyLogin($this, $user);

    $this->assertAuthenticatedAs($user, 'identity');
});

it('still requires a challenge after passkey login when the pipeline demands MFA', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    $factor = app(TwoFactorManager::class)->enable($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    Oidc::postLogin(fn (LoginEvent $e, LoginApi $api) => $api->requireMfa());

    finalizationPasskeyLogin($this, $user)->assertRedirect(route(Handler::TwoFactorLogin->value));

    $this->assertGuest('identity');
});
