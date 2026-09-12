<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Actions;

use Bambamboole\LaravelOidc\Server\Credentials\Events\MfaChallengeFailed;
use Bambamboole\LaravelOidc\Server\Credentials\Events\MfaChallengeSucceeded;
use Bambamboole\LaravelOidc\Server\Credentials\Events\RecoveryCodeUsed;
use Bambamboole\LaravelOidc\Server\Credentials\FactorChallenge;
use Bambamboole\LaravelOidc\Server\Credentials\FactorEnrollment;
use Bambamboole\LaravelOidc\Server\Credentials\FactorRegistry;
use Bambamboole\LaravelOidc\Server\Credentials\FactorVerification;
use Bambamboole\LaravelOidc\Server\Credentials\PendingMfaChallenge;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * A recovery code answers any pending factor; otherwise the proof is checked
 * against the enrollment the challenge was issued for. Every outcome is
 * audited here; establishing the session afterwards is the caller's job.
 */
readonly class VerifyFactorChallenge
{
    public function __construct(
        protected FactorRegistry $factors,
    ) {}

    /**
     * @param  array<string, mixed>  $proof  `code`, `recovery_code`, or `credential`
     */
    public function __invoke(Authenticatable $user, PendingMfaChallenge $pending, array $proof): ?FactorVerification
    {
        $usesRecoveryCode = isset($proof['recovery_code']) && $proof['recovery_code'] !== '';
        $providerKey = $usesRecoveryCode ? 'recovery_code' : $pending->factor;
        $provider = $this->factors->get($providerKey);
        $enrollment = $usesRecoveryCode
            ? $provider->enrollments($user)[0] ?? null
            : $this->pendingEnrollment($user, $providerKey, $pending->factorId);

        if (! $enrollment instanceof FactorEnrollment) {
            event(new MfaChallengeFailed((string) $pending->userId, $providerKey, 'unknown_enrollment'));

            return null;
        }

        $challenge = new FactorChallenge($enrollment, privateState: PendingMfaChallenge::pullChallengeState());
        $verification = $provider->verify($user, $challenge, $proof);

        if (! $verification->verified) {
            event(new MfaChallengeFailed((string) $pending->userId, $providerKey, 'invalid_code'));

            return null;
        }

        event(new MfaChallengeSucceeded((string) $pending->userId, $providerKey));

        if ($usesRecoveryCode) {
            event(new RecoveryCodeUsed((string) $pending->userId));
        }

        return $verification;
    }

    protected function pendingEnrollment(Authenticatable $user, string $providerKey, string $id): ?FactorEnrollment
    {
        foreach ($this->factors->get($providerKey)->enrollments($user) as $enrollment) {
            if ($id === '' || $enrollment->id === $id) {
                return $enrollment;
            }
        }

        return null;
    }
}
