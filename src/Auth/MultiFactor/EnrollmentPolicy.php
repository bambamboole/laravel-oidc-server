<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The recovery-code lifecycle rules shared by every enrollment surface (the
 * HTTP enrollment endpoints and the ui components): backup codes cover every
 * factor type, so they are backfilled once any factor is confirmed and removed
 * once no challengeable factor remains.
 */
class EnrollmentPolicy
{
    public function __construct(
        private readonly FactorRegistry $factors,
        private readonly RecoveryCodeProvider $recoveryCodes,
    ) {}

    /**
     * Returns whether recovery codes were backfilled, so callers can surface
     * the fresh codes to the user.
     */
    public function factorConfirmed(Authenticatable $user): bool
    {
        if ($this->recoveryCodes->enrollments($user) === []) {
            $this->recoveryCodes->generate($user);

            return true;
        }

        return false;
    }

    public function factorRevoked(Authenticatable $user): void
    {
        if ($this->factors->challengeableEnrollments($user) === []) {
            $this->recoveryCodes->clear($user);
        }
    }
}
