<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Enums\FactorRole;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Enums\FactorSetupKind;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\RecoveryCodeProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\TotpFactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\WebAuthn\AttachmentAwareRegistrationOptions;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\WebAuthnFactorProvider;
use Laravel\Passkeys\Actions\GenerateRegistrationOptions;
use Webauthn\AuthenticatorSelectionCriteria;
use Workbench\App\Models\User;

it('offers a platform passkey and a roaming security key over the same provider', function () {
    $options = app(WebAuthnFactorProvider::class)->enrollmentOptions();

    expect(array_column($options, 'id'))->toBe(['passkey', 'security_key'])
        ->and(array_unique(array_column($options, 'providerKey')))->toBe(['webauthn']);

    [$passkey, $securityKey] = $options;

    expect($passkey->recommended)->toBeTrue()
        ->and($passkey->role)->toBe(FactorRole::LoginAndSecondFactor)
        ->and($passkey->setupKind)->toBe(FactorSetupKind::Ceremony)
        ->and($passkey->hints['attachment'])->toBe(AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM)
        ->and($securityKey->recommended)->toBeFalse()
        ->and($securityKey->role)->toBe(FactorRole::LoginAndSecondFactor)
        ->and($securityKey->hints['attachment'])->toBe(AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM);
});

it('offers a code-based second factor for the authenticator app', function () {
    $options = app(TotpFactorProvider::class)->enrollmentOptions();

    expect($options)->toHaveCount(1)
        ->and($options[0]->id)->toBe('totp')
        ->and($options[0]->role)->toBe(FactorRole::SecondFactorOnly)
        ->and($options[0]->setupKind)->toBe(FactorSetupKind::Code);
});

it('keeps recovery codes out of the method picker', function () {
    expect(app(RecoveryCodeProvider::class)->enrollmentOptions())->toBe([]);
});

it('asks for the named attachment without loosening the other ceremony criteria', function (string $attachment) {
    $default = (new GenerateRegistrationOptions)->authenticatorSelection();
    $selection = (new AttachmentAwareRegistrationOptions($attachment))->authenticatorSelection();

    expect($selection->authenticatorAttachment)->toBe($attachment)
        ->and($selection->residentKey)->toBe($default->residentKey)
        ->and($selection->userVerification)->toBe($default->userVerification);
})->with([
    AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
    AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
]);

it('leaves the attachment unconstrained for the ordinary passkey ceremony', function () {
    expect((new GenerateRegistrationOptions)->authenticatorSelection()->authenticatorAttachment)
        ->toBe(AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE);
});

it('reports how many recovery codes of the generated set are left', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $provider = app(RecoveryCodeProvider::class);

    expect($provider->remaining($user))->toBe(0)
        ->and($provider->total($user))->toBe(0);

    config(['oidc.auth.two_factor.recovery_codes' => 4]);
    $codes = $provider->generate($user);

    expect($provider->remaining($user))->toBe(4)
        ->and($provider->total($user))->toBe(4);

    $provider->verify($user, $provider->beginChallenge($user, $provider->enrollments($user)[0]), [
        'recovery_code' => $codes[0],
    ]);

    expect($provider->remaining($user))->toBe(3)
        ->and($provider->total($user))->toBe(4);
});
