<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Actions;

use Bambamboole\LaravelOidc\Server\Credentials\Contracts\EnrollableFactorProvider;
use Bambamboole\LaravelOidc\Server\Credentials\EnrollmentPolicy;
use Bambamboole\LaravelOidc\Server\Credentials\FactorEnrollment;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Illuminate\Contracts\Auth\Authenticatable;

final readonly class RevokeFactor
{
    public function __construct(
        private EnrollmentPolicy $policy,
        private Auditor $auditor,
    ) {}

    public function __invoke(Authenticatable $user, EnrollableFactorProvider $provider, FactorEnrollment $enrollment): void
    {
        $provider->revoke($user, $enrollment);
        $this->policy->factorRevoked($user);

        $this->auditor->log(AuditEventType::FactorRevoked, userId: (string) $user->getAuthIdentifier(), context: [
            'factor' => $provider->key(),
            'enrollment_id' => $enrollment->id,
        ]);
    }
}
