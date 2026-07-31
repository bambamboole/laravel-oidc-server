<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor;

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts\EnrollableFactorProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passkeys\Actions\GenerateRegistrationOptions;
use Laravel\Passkeys\Actions\GenerateVerificationOptions;
use Laravel\Passkeys\Actions\StorePasskey;
use Laravel\Passkeys\Actions\VerifyPasskey;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Passkey;
use Laravel\Passkeys\Support\WebAuthn;
use Throwable;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * Passkeys as a second factor. Enrollment is a two-step ceremony: begin
 * returns the WebAuthn creation options (in the enrollment metadata) and
 * parks them in the session as a synthetic `pending` enrollment; confirm
 * validates the attestation credential and stores the passkey.
 */
class WebAuthnFactorProvider implements EnrollableFactorProvider
{
    private const string PENDING_KEY = 'oidc.webauthn.enrollment';

    public const string PENDING_ID = 'pending';

    public function __construct(
        private readonly GenerateVerificationOptions $generateOptions,
        private readonly VerifyPasskey $verifyPasskey,
        private readonly GenerateRegistrationOptions $generateRegistrationOptions,
        private readonly StorePasskey $storePasskey,
    ) {}

    public function key(): string
    {
        return 'webauthn';
    }

    public function isBackup(): bool
    {
        return false;
    }

    /**
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array
    {
        if (! $user instanceof PasskeyUser) {
            return [];
        }

        $enrollments = $user->passkeys()->get()->map(fn (Passkey $passkey): FactorEnrollment => new FactorEnrollment(
            $this->key(),
            (string) $passkey->getKey(),
            $passkey->name,
            $passkey->created_at,
            $passkey->last_used_at,
            [
                'authenticator' => $passkey->authenticator,
                'credential_id' => $passkey->credential_id,
            ],
        ))->all();

        $pending = session()->get(self::PENDING_KEY);

        if (is_array($pending)) {
            $enrollments[] = new FactorEnrollment(
                $this->key(),
                self::PENDING_ID,
                (string) ($pending['name'] ?? 'Passkey'),
                null,
                null,
            );
        }

        return $enrollments;
    }

    public function beginEnrollment(Authenticatable $user, ?string $name = null): FactorEnrollment
    {
        if (! $user instanceof PasskeyUser) {
            abort(403);
        }

        $options = ($this->generateRegistrationOptions)($user);
        $name ??= 'Passkey';

        session()->put(self::PENDING_KEY, [
            'options' => WebAuthn::toJson($options),
            'name' => $name,
        ]);

        return new FactorEnrollment(
            $this->key(),
            self::PENDING_ID,
            $name,
            null,
            null,
            ['options' => WebAuthn::toBrowserArray($options)],
        );
    }

    public function confirmEnrollment(Authenticatable $user, FactorEnrollment $enrollment, FactorResponse $response): bool
    {
        $pending = session()->get(self::PENDING_KEY);
        $credential = $response->input['credential'] ?? null;

        if ($enrollment->id !== self::PENDING_ID || ! is_array($pending) || ! is_array($credential)) {
            return false;
        }

        try {
            ($this->storePasskey)(
                $user,
                (string) ($pending['name'] ?? 'Passkey'),
                WebAuthn::fromJson((string) json_encode($credential), PublicKeyCredential::class),
                WebAuthn::fromJson((string) $pending['options'], PublicKeyCredentialCreationOptions::class),
            );
        } catch (Throwable) {
            return false;
        }

        session()->forget(self::PENDING_KEY);

        return true;
    }

    public function revoke(Authenticatable $user, FactorEnrollment $enrollment): void
    {
        if ($enrollment->id === self::PENDING_ID) {
            session()->forget(self::PENDING_KEY);

            return;
        }

        if ($user instanceof PasskeyUser) {
            $user->passkeys()->whereKey($enrollment->id)->delete();
        }
    }

    public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge
    {
        if (! $user instanceof PasskeyUser) {
            return new FactorChallenge($enrollment);
        }

        $options = ($this->generateOptions)($user);

        return new FactorChallenge(
            $enrollment,
            ['options' => WebAuthn::toBrowserArray($options)],
            ['options' => WebAuthn::toJson($options)],
        );
    }

    public function verify(Authenticatable $user, FactorChallenge $challenge, FactorResponse $response): FactorVerification
    {
        if (! $user instanceof PasskeyUser) {
            return new FactorVerification(false);
        }

        $credential = $response->input['credential'] ?? null;
        $serializedOptions = $challenge->privateState['options'] ?? null;

        if (! is_array($credential) || ! is_string($serializedOptions)) {
            return new FactorVerification(false);
        }

        try {
            // VerifyPasskey scopes the credential to $user, so any of the
            // user's passkeys satisfies the challenge — the challenge options
            // allow all of them, so verification must not pin to the one
            // enrollment the challenge was stashed with.
            ($this->verifyPasskey)(
                WebAuthn::fromJson((string) json_encode($credential), PublicKeyCredential::class),
                WebAuthn::fromJson($serializedOptions, PublicKeyCredentialRequestOptions::class),
                $user,
            );
        } catch (Throwable) {
            return new FactorVerification(false);
        }

        return new FactorVerification(true, ['webauthn'], [
            'phishing_resistant' => true,
            'user_verified' => true,
        ]);
    }
}
