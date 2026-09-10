<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials;

use Bambamboole\LaravelOidc\Server\Shared\Credentials\SecondFactorGate;
use Illuminate\Contracts\Auth\Authenticatable;
use LogicException;

final readonly class EnrolledFactorGate implements SecondFactorGate
{
    public function __construct(private FactorRegistry $factors) {}

    public function hasChallengeableFactors(Authenticatable $user): bool
    {
        return $this->factors->configuredChallengeableEnrollments($user) !== [];
    }

    public function canEnrollFactor(Authenticatable $user): bool
    {
        return $this->factors->enrollmentOptions() !== [];
    }

    public function beginChallenge(Authenticatable $user, bool $remember): void
    {
        $enrollments = $this->factors->configuredChallengeableEnrollments($user);

        if ($enrollments === []) {
            throw new LogicException('Cannot begin a second-factor challenge for a user without challengeable factors.');
        }

        new PendingMfaChallenge(
            userId: $user->getAuthIdentifier(),
            remember: $remember,
            factor: $enrollments[0]->providerKey,
            factorId: $enrollments[0]->id,
        )->store();
    }
}
