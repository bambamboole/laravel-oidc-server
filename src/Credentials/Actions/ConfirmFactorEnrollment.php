<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Actions;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Credentials\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Credentials\EnrollmentPolicy;
use Bambamboole\LaravelOidc\Server\Credentials\FactorEnrollment;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Completes a pending enrollment with the provider-specific proof (a TOTP
 * code, a WebAuthn attestation). Returns false when the proof is rejected.
 */
final class ConfirmFactorEnrollment
{
    public function __construct(
        private readonly EnrollmentPolicy $policy,
        private readonly Auditor $auditor,
    ) {}

    /**
     * @param  array<string, mixed>  $proof
     */
    public function __invoke(
        Authenticatable $user,
        EnrollableFactorProvider $provider,
        FactorEnrollment $enrollment,
        array $proof,
    ): bool {
        if (! $provider->confirmEnrollment($user, $enrollment, $proof)) {
            return false;
        }

        $this->policy->factorConfirmed($user);

        $this->auditor->log(AuditEventType::FactorConfirmed, userId: (string) $user->getAuthIdentifier(), context: [
            'factor' => $provider->key(),
            'enrollment_id' => $enrollment->id,
        ]);

        return true;
    }
}
