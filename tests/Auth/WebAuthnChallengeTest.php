<?php

declare(strict_types=1);

/**
 * WebAuthn as a deferred second factor: the challenge is issued in one
 * request (options persisted server-side) and verified in the next.
 */

use Bambamboole\LaravelOidc\Auth\AuthenticationMethods;
use Bambamboole\LaravelOidc\Routing\Handler;
use Illuminate\Support\Facades\Hash;
use Laravel\Passkeys\Actions\VerifyPasskey;
use Laravel\Passkeys\Contracts\PasskeyUser;
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
    expect(session(AuthenticationMethods::SESSION_KEY))->toContain('webauthn');
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

it('consumes the challenge state on a failed attempt', function () {
    [$user, $passkey] = webauthnChallengeUser();
    $otherUser = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => Hash::make('password')]);
    $otherPasskey = $otherUser->passkeys()->create([
        'name' => 'Other', 'credential_id' => Base64UrlSafe::encodeUnpadded(random_bytes(16)), 'credential' => ['type' => 'public-key'],
    ]);
    stubVerifiedPasskey($otherPasskey);

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
