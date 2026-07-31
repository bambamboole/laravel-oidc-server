<?php

declare(strict_types=1);

/**
 * Provider-keyed factor enrollment: any registered EnrollableFactorProvider
 * gets enroll/confirm/revoke endpoints and appears in the factor listing, so
 * new factor types need no package changes.
 */

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Models\TotpFactor;
use Bambamboole\LaravelOidc\Server\Routing\Handler;
use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Hash;
use Laravel\Passkeys\Actions\StorePasskey;
use Laravel\Passkeys\Passkey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PragmaRX\Google2FA\Google2FA;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Workbench\App\Models\User;

function enrollmentUser(): User
{
    return User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
}

function actingAsEnrollmentUser(mixed $test, User $user): mixed
{
    return $test->actingAs($user, 'identity')->withSession(['auth.password_confirmed_at' => time()]);
}

/**
 * A structurally valid "none"-format attestation credential: enough to pass
 * WebAuthn deserialization so the (stubbed) StorePasskey handoff is reached.
 *
 * @return array<string, mixed>
 */
function webauthnAttestationPayload(): array
{
    $coseKey = MapObject::create()
        ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
        ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
        ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
        ->add(NegativeIntegerObject::create(-2), ByteStringObject::create(str_repeat("\x01", 32)))
        ->add(NegativeIntegerObject::create(-3), ByteStringObject::create(str_repeat("\x02", 32)));

    $authData = str_repeat("\x00", 32).chr(0x41).pack('N', 0)
        .str_repeat("\x00", 16).pack('n', 4).'cred'
        .(string) $coseKey;

    $attestationObject = (string) MapObject::create()
        ->add(TextStringObject::create('fmt'), TextStringObject::create('none'))
        ->add(TextStringObject::create('attStmt'), MapObject::create())
        ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

    return [
        'id' => 'Y3JlZA',
        'rawId' => 'Y3JlZA',
        'type' => 'public-key',
        'authenticatorAttachment' => null,
        'response' => [
            'clientDataJSON' => Base64UrlSafe::encodeUnpadded((string) json_encode([
                'type' => 'webauthn.create', 'challenge' => 'AQIDBA', 'origin' => 'http://localhost',
            ])),
            'attestationObject' => Base64UrlSafe::encodeUnpadded($attestationObject),
        ],
    ];
}

it('lists enrollments across all providers', function () {
    $user = enrollmentUser();
    $user->totpFactors()->create(['name' => 'Authenticator app', 'secret' => 'SECRET', 'confirmed_at' => now()]);
    $user->passkeys()->create(['name' => 'My key', 'credential_id' => 'AQIDBA', 'credential' => ['type' => 'public-key']]);

    actingAsEnrollmentUser($this, $user)
        ->getJson(route(Handler::TwoFactorFactors->value))
        ->assertOk()
        ->assertJsonFragment(['provider' => 'totp'])
        ->assertJsonFragment(['provider' => 'webauthn']);
});

it('enrolls a factor through its provider key', function () {
    $user = enrollmentUser();

    $response = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->assertCreated();

    expect($response->json('provider'))->toBe('totp')
        ->and($response->json('metadata.secret'))->toBeString();

    $factor = $user->totpFactors()->latest('id')->first();
    expect($factor)->not->toBeNull()
        ->and($factor->confirmed_at)->toBeNull();
});

it('confirms an enrollment and backfills recovery codes', function () {
    $user = enrollmentUser();

    $enrollment = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->json();

    $code = app(Google2FA::class)->getCurrentOtp($enrollment['metadata']['secret']);

    actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnrollConfirm->value, ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => $code,
        ])->assertOk();

    expect($user->totpFactors()->whereNotNull('confirmed_at')->exists())->toBeTrue()
        ->and($user->recoveryCodes()->count())->toBeGreaterThan(0);
});

it('returns the existing pending enrollment instead of stacking rows', function () {
    $user = enrollmentUser();

    $first = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->json();

    $second = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->assertCreated()
        ->json();

    expect($user->totpFactors()->count())->toBe(1)
        ->and($second['id'])->toBe($first['id'])
        ->and($second['metadata']['secret'])->toBe($first['metadata']['secret']);
});

it('begins a fresh pending enrollment alongside a confirmed factor', function () {
    $user = enrollmentUser();
    $confirmed = $user->totpFactors()->create(['name' => 'Authenticator app', 'secret' => 'SECRET']);
    $confirmed->forceFill(['confirmed_at' => now()])->save();

    $enrollment = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->assertCreated()
        ->json();

    expect($user->totpFactors()->count())->toBe(2)
        ->and($enrollment['id'])->not->toBe((string) $confirmed->getKey())
        ->and($confirmed->refresh()->confirmed_at)->not->toBeNull();
});

it('rejects an enrollment confirmation with an invalid code', function () {
    $user = enrollmentUser();

    $enrollment = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))
        ->json();

    actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnrollConfirm->value, ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => '000000',
        ])->assertUnprocessable();

    expect($user->totpFactors()->whereNotNull('confirmed_at')->exists())->toBeFalse();
});

it('revokes an enrollment', function () {
    $user = enrollmentUser();
    $factor = $user->totpFactors()->create(['name' => 'Authenticator app', 'secret' => 'SECRET', 'confirmed_at' => now()]);

    actingAsEnrollmentUser($this, $user)
        ->deleteJson(route(Handler::TwoFactorRevoke->value, ['provider' => 'totp', 'enrollment' => $factor->getKey()]))
        ->assertNoContent();

    expect(TotpFactor::query()->whereKey($factor->getKey())->exists())->toBeFalse();
});

it('returns 404 for an unknown provider', function () {
    $user = enrollmentUser();

    actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'sms']))
        ->assertNotFound();
});

it('enrolls a passkey through the generic webauthn ceremony', function () {
    config(['passkeys.user_handle_secret' => 'user-handle-secret']);
    $user = enrollmentUser();

    // The attestation validation itself belongs to laravel/passkeys; stub the
    // store action (before the provider singleton captures the real one) to
    // observe the handoff.
    app()->instance(StorePasskey::class, new class($user) extends StorePasskey
    {
        public function __construct(private readonly User $owner) {}

        public function __invoke(
            Authenticatable $user,
            string $name,
            PublicKeyCredential $credential,
            PublicKeyCredentialCreationOptions $options
        ): Passkey {
            return $this->owner->passkeys()->create([
                'name' => $name,
                'credential_id' => 'stub-credential',
                'credential' => [],
            ]);
        }
    });

    $begin = actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'webauthn']), ['name' => 'Yubikey'])
        ->assertCreated()
        ->json();

    expect($begin['id'])->toBe('pending')
        ->and($begin['metadata']['options'])->toBeArray()
        ->and(session('oidc.webauthn.enrollment'))->toBeArray();

    actingAsEnrollmentUser($this, $user)
        ->postJson(route(Handler::TwoFactorEnrollConfirm->value, ['provider' => 'webauthn']), [
            'enrollment_id' => 'pending',
            'credential' => webauthnAttestationPayload(),
        ])->assertOk();

    $passkey = $user->passkeys()->firstOrFail();

    expect($passkey->name)->toBe('Yubikey')
        ->and(session('oidc.webauthn.enrollment'))->toBeNull()
        ->and($user->recoveryCodes()->count())->toBeGreaterThan(0);

    actingAsEnrollmentUser($this, $user)
        ->deleteJson(route(Handler::TwoFactorRevoke->value, ['provider' => 'webauthn', 'enrollment' => $passkey->getKey()]))
        ->assertNoContent();

    expect($user->passkeys()->count())->toBe(0);
});

it('requires authentication', function () {
    $this->postJson(route(Handler::TwoFactorEnroll->value, ['provider' => 'totp']))->assertUnauthorized();
});
