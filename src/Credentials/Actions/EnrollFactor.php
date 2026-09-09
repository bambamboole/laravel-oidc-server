<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Actions;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Credentials\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Credentials\Data\EnrollmentOption;
use Bambamboole\LaravelOidc\Server\Credentials\FactorEnrollment;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Starts an enrollment ceremony with the given provider. Multi-step
 * ceremonies (webauthn) return their public options in the enrollment
 * metadata and complete through ConfirmFactorEnrollment.
 */
final class EnrollFactor
{
    public function __construct(private readonly Auditor $auditor) {}

    public function __invoke(
        Authenticatable $user,
        EnrollableFactorProvider $provider,
        ?EnrollmentOption $option = null,
        ?string $name = null,
    ): FactorEnrollment {
        $enrollment = $provider->beginEnrollment($user, $option, $name);

        $this->auditor->log(AuditEventType::FactorEnrollmentStarted, userId: (string) $user->getAuthIdentifier(), context: [
            'factor' => $provider->key(),
            'enrollment_id' => $enrollment->id,
        ]);

        return $enrollment;
    }
}
