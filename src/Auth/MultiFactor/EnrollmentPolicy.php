<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor;

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Concerns\InteractsWithFactorUser;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The recovery-code lifecycle rules shared by every enrollment surface (the
 * HTTP enrollment endpoints and the ui components): backup codes cover every
 * factor type, so they are backfilled once any factor is confirmed and removed
 * once no challengeable factor remains.
 */
class EnrollmentPolicy
{
    use InteractsWithFactorUser;

    public function __construct(
        private readonly FactorRegistry $factors,
        private readonly RecoveryCodeProvider $recoveryCodes,
    ) {}

    public function factorConfirmed(Authenticatable $user): void
    {
        if ($this->recoveryCodes->enrollments($user) === []) {
            $this->recoveryCodes->generate($user);
        }
    }

    public function factorRevoked(Authenticatable $user): void
    {
        if ($this->factors->challengeableEnrollments($user) === []) {
            $this->factorUser($user)->recoveryCodes()->delete();
        }
    }
}
