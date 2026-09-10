<?php

declare(strict_types=1);

/**
 * Multi-factor login: password → deferred second-factor challenge (TOTP, recovery code, WebAuthn) → session;
 * RFC 8176 (amr values pwd, otp, webauthn)
 */

use Bambamboole\LaravelOidc\Server\Credentials\RecoveryCodeProvider;
use Bambamboole\LaravelOidc\Server\Credentials\TotpFactorProvider;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AuthSessionState;
use Illuminate\Support\Facades\Hash;
use Laravel\Passkeys\Actions\VerifyPasskey;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Passkey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PragmaRX\Google2FA\Google2FA;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
});

function mfaEnrollTotp(User $user): string
{
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();
    app(RecoveryCodeProvider::class)->generate($user);

    return $factor->secret;
}

function mfaEnrollPasskey(User $user): Passkey
{
    $passkey = $user->passkeys()->create([
        'name' => 'Key',
        'credential_id' => Base64UrlSafe::encodeUnpadded(random_bytes(16)),
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

    return $passkey;
}

/**
 * @return array<string, mixed>
 */
function mfaAssertionPayload(): array
{
    return [
        'id' => 'AQIDBA',
        'rawId' => 'AQIDBA',
        'type' => 'public-key',
        'authenticatorAttachment' => null,
        'response' => [
            'clientDataJSON' => Base64UrlSafe::encodeUnpadded((string) json_encode([
                'type' => 'webauthn.get', 'challenge' => 'AQIDBA', 'origin' => 'http://localhost',
            ])),
            'authenticatorData' => Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32)."\x01".pack('N', 1)),
            'signature' => 'AQIDBA',
            'userHandle' => null,
        ],
    ];
}

it('defers the login until the TOTP challenge is verified and records both methods', function () {
    $secret = mfaEnrollTotp($this->user);

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password', 'remember' => true])
        ->assertRedirect(route('identity.two-factor.login'))
        ->assertSessionHas('login.id', $this->user->getAuthIdentifier())
        ->assertSessionHas('login.remember', true);

    $this->assertGuest('identity');

    $this->post(route('identity.two-factor.login.store'), ['code' => app(Google2FA::class)->getCurrentOtp($secret)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user, 'identity');
    expect(session(AuthSessionState::AMR_KEY))->toBe(['pwd', 'otp']);
});

it('signals the pending challenge to JSON clients', function () {
    mfaEnrollTotp($this->user);

    $this->postJson(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])
        ->assertOk()
        ->assertJson(['two_factor' => true]);

    $this->assertGuest('identity');
});

it('completes the challenge with a recovery code, consuming it', function () {
    mfaEnrollTotp($this->user);
    $recoveryCode = $this->user->recoveryCodes()->firstOrFail()->code;

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])
        ->assertRedirect(route('identity.two-factor.login'));

    $this->post(route('identity.two-factor.login.store'), ['recovery_code' => $recoveryCode])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user, 'identity');
    expect(session(AuthSessionState::AMR_KEY))->toBe(['pwd', 'otp'])
        ->and($this->user->recoveryCodes()->whereNull('used_at')->count())->toBe(7);
});

it('completes a WebAuthn second-factor challenge through the options and assertion legs', function () {
    config(['oidc.auth.two_factor.challenge_providers' => ['webauthn']]);
    mfaEnrollPasskey($this->user);

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])
        ->assertRedirect(route('identity.two-factor.login'));

    $this->assertGuest('identity');

    $this->getJson(route('identity.two-factor.login.options'))->assertOk()->assertJsonStructure(['options']);

    $this->post(route('identity.two-factor.login.store'), ['credential' => mfaAssertionPayload()])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user, 'identity');
    expect(session(AuthSessionState::AMR_KEY))->toBe(['pwd', 'webauthn']);
});

it('lets the user switch from the default TOTP challenge to a passkey mid-challenge', function () {
    mfaEnrollTotp($this->user);
    mfaEnrollPasskey($this->user);

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])
        ->assertRedirect(route('identity.two-factor.login'))
        ->assertSessionHas('login.factor', 'totp');

    $this->get(route('identity.two-factor.login.factor', ['provider' => 'webauthn']))
        ->assertRedirect(route('identity.two-factor.login'))
        ->assertSessionHas('login.factor', 'webauthn');

    $this->getJson(route('identity.two-factor.login.options'))->assertOk();

    $this->post(route('identity.two-factor.login.store'), ['credential' => mfaAssertionPayload()])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user, 'identity');
});

it('challenges a password login with an enrolled passkey only while webauthn is a challenge provider', function () {
    $this->user->passkeys()->create(['name' => 'Security key', 'credential_id' => 'credential-id', 'credential' => []]);

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])
        ->assertRedirect(route('identity.two-factor.login', absolute: false));

    expect(session('login.factor'))->toBe('webauthn');
    $this->assertGuest('identity');

    config(['oidc.auth.two_factor.challenge_providers' => ['totp']]);

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user, 'identity');
});
