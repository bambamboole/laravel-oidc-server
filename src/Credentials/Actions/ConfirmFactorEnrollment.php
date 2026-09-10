<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Actions;

use Bambamboole\LaravelOidc\Server\Credentials\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Credentials\EnrollmentPolicy;
use Bambamboole\LaravelOidc\Server\Credentials\FactorEnrollment;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Illuminate\Contracts\Auth\Authenticatable;

final readonly class ConfirmFactorEnrollment
{
    public function __construct(
        private EnrollmentPolicy $policy,
        private Auditor $auditor,
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
