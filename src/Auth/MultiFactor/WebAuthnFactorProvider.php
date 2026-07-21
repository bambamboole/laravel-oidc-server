<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor;

use Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts\FactorProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passkeys\Actions\GenerateVerificationOptions;
use Laravel\Passkeys\Actions\VerifyPasskey;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Passkey;
use Laravel\Passkeys\Support\WebAuthn;
use Throwable;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;

class WebAuthnFactorProvider implements FactorProvider
{
    public function __construct(
        private readonly GenerateVerificationOptions $generateOptions,
        private readonly VerifyPasskey $verifyPasskey,
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

        return $user->passkeys()->get()->map(fn (Passkey $passkey): FactorEnrollment => new FactorEnrollment(
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
            $passkey = ($this->verifyPasskey)(
                WebAuthn::fromJson((string) json_encode($credential), PublicKeyCredential::class),
                WebAuthn::fromJson($serializedOptions, PublicKeyCredentialRequestOptions::class),
                $user,
            );
        } catch (Throwable) {
            return new FactorVerification(false);
        }

        $verified = (string) $passkey->getKey() === $challenge->enrollment->id;

        return new FactorVerification($verified, $verified ? ['webauthn'] : [], [
            'phishing_resistant' => true,
            'user_verified' => true,
        ]);
    }
}
