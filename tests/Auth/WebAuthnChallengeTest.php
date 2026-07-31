<?php

declare(strict_types=1);

/**
 * WebAuthn as a deferred second factor: the challenge is issued in one
 * request (options persisted server-side) and verified in the next.
 */

use Bambamboole\LaravelOidc\Server\Auth\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\TotpFactorProvider;
use Bambamboole\LaravelOidc\Server\Routing\Handler;
use Illuminate\Support\Facades\Hash;
use Laravel\Passkeys\Actions\VerifyPasskey;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Exceptions\InvalidPasskeyException;
use Laravel\Passkeys\Passkey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Workbench\App\Models\User;

/**
 * @return array{User, Passkey}
 */
function webauthnChallengeUser(): array
{
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    $passkey = $user->passkeys()->create([
        'name' => 'Key',
        'credential_id' => Base64UrlSafe::encodeUnpadded(random_bytes(16)),
        'credential' => ['type' => 'public-key'],
    ]);

    return [$user, $passkey];
}

function stubVerifiedPasskey(Passkey $passkey): void
{
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
}

/**
 * @return array<string, mixed>
 */
function webauthnAssertionPayload(): array
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

it('issues webauthn challenge options and stores the private state', function () {
    [$user, $passkey] = webauthnChallengeUser();

    $this->withSession([
        'login.id' => $user->getAuthIdentifier(),
        'login.factor' => 'webauthn',
        'login.factor_id' => (string) $passkey->getKey(),
    ])->getJson(route(Handler::TwoFactorChallengeOptions->value))
        ->assertOk()
        ->assertJsonStructure(['options']);

    expect(session('login.challenge_state'))->toBeArray()->toHaveKey('options');
});

it('rejects options requests without a pending challenge', function () {
    $this->getJson(route(Handler::TwoFactorChallengeOptions->value))->assertUnauthorized();
});

it('completes a webauthn second-factor challenge end to end', function () {
    [$user, $passkey] = webauthnChallengeUser();
    config(['oidc.auth.two_factor.challenge_providers' => ['webauthn']]);
    stubVerifiedPasskey($passkey);

    $this->post(route(Handler::LoginStore->value), [
        'email' => 'm@example.com',
        'password' => 'password',
    ])->assertRedirect(route(Handler::TwoFactorLogin->value));

    $this->assertGuest('identity');

    $this->getJson(route(Handler::TwoFactorChallengeOptions->value))->assertOk();

    $this->post(route(Handler::TwoFactorLoginStore->value), [
        'credential' => webauthnAssertionPayload(),
    ])->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user, 'identity');
    expect(session(AuthSessionState::AMR_KEY))->toContain('webauthn');
});

it('completes a challenge after switching from totp to webauthn', function () {
    [$user, $passkey] = webauthnChallengeUser();
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();
    stubVerifiedPasskey($passkey);

    $this->post(route(Handler::LoginStore->value), [
        'email' => 'm@example.com',
        'password' => 'password',
    ])->assertRedirect(route(Handler::TwoFactorLogin->value))
        ->assertSessionHas('login.factor', 'totp');

    $this->get(route(Handler::TwoFactorLoginFactor->value, ['provider' => 'webauthn']))
        ->assertRedirect(route(Handler::TwoFactorLogin->value))
        ->assertSessionHas('login.factor', 'webauthn');

    $this->getJson(route(Handler::TwoFactorChallengeOptions->value))->assertOk();

    $this->post(route(Handler::TwoFactorLoginStore->value), [
        'credential' => webauthnAssertionPayload(),
    ])->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user, 'identity');
    expect(session(AuthSessionState::AMR_KEY))->toContain('webauthn');
});

it('rejects a webauthn assertion when no challenge was issued', function () {
    [$user, $passkey] = webauthnChallengeUser();
    stubVerifiedPasskey($passkey);

    $this->withSession([
        'login.id' => $user->getAuthIdentifier(),
        'login.factor' => 'webauthn',
        'login.factor_id' => (string) $passkey->getKey(),
    ])->post(route(Handler::TwoFactorLoginStore->value), [
        'credential' => webauthnAssertionPayload(),
    ])->assertSessionHasErrors('code');

    $this->assertGuest('identity');
});

it('accepts any of the users passkeys, not only the pinned enrollment', function () {
    [$user, $passkey] = webauthnChallengeUser();
    $secondPasskey = $user->passkeys()->create([
        'name' => 'Backup key', 'credential_id' => Base64UrlSafe::encodeUnpadded(random_bytes(16)), 'credential' => ['type' => 'public-key'],
    ]);
    stubVerifiedPasskey($secondPasskey);

    $this->withSession([
        'login.id' => $user->getAuthIdentifier(),
        'login.factor' => 'webauthn',
        'login.factor_id' => (string) $passkey->getKey(),
    ])->getJson(route(Handler::TwoFactorChallengeOptions->value))->assertOk();

    $this->post(route(Handler::TwoFactorLoginStore->value), [
        'credential' => webauthnAssertionPayload(),
    ])->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user, 'identity');
});

it('consumes the challenge state on a failed attempt', function () {
    [$user, $passkey] = webauthnChallengeUser();
    // VerifyPasskey rejects assertions that fail validation or belong to
    // another user; simulate that rejection.
    app()->instance(VerifyPasskey::class, new class extends VerifyPasskey
    {
        public function __construct() {}

        public function __invoke(
            PublicKeyCredential $credential,
            PublicKeyCredentialRequestOptions $options,
            ?PasskeyUser $user = null,
        ): Passkey {
            throw InvalidPasskeyException::make('Unable to verify passkey.');
        }
    });

    $this->withSession([
        'login.id' => $user->getAuthIdentifier(),
        'login.factor' => 'webauthn',
        'login.factor_id' => (string) $passkey->getKey(),
    ])->getJson(route(Handler::TwoFactorChallengeOptions->value))->assertOk();

    $this->post(route(Handler::TwoFactorLoginStore->value), [
        'credential' => webauthnAssertionPayload(),
    ])->assertSessionHasErrors('code');

    expect(session('login.challenge_state'))->toBeNull();
    $this->assertGuest('identity');
});
