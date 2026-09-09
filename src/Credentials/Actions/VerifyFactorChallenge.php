<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Actions;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Credentials\FactorChallenge;
use Bambamboole\LaravelOidc\Server\Credentials\FactorEnrollment;
use Bambamboole\LaravelOidc\Server\Credentials\FactorRegistry;
use Bambamboole\LaravelOidc\Server\Credentials\FactorVerification;
use Bambamboole\LaravelOidc\Server\Credentials\PendingMfaChallenge;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Verifies the second factor for a pending challenge. A recovery code
 * answers any pending factor; otherwise the proof is checked against the
 * enrollment the challenge was issued for. Returns null when the proof is
 * rejected; every outcome is audited here. Establishing the session
 * afterwards is the caller's job.
 */
final class VerifyFactorChallenge
{
    public function __construct(
        private readonly FactorRegistry $factors,
        private readonly Auditor $auditor,
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
            $this->auditor->log(AuditEventType::MfaChallengeFailed, userId: (string) $pending->userId, context: [
                'factor' => $providerKey,
                'reason' => 'unknown_enrollment',
            ]);

            return null;
        }

        $challenge = new FactorChallenge($enrollment, privateState: PendingMfaChallenge::pullChallengeState());
        $verification = $provider->verify($user, $challenge, $proof);

        if (! $verification->verified) {
            $this->auditor->log(AuditEventType::MfaChallengeFailed, userId: (string) $pending->userId, context: [
                'factor' => $providerKey,
                'reason' => 'invalid_code',
            ]);

            return null;
        }

        $this->auditor->log(AuditEventType::MfaChallengeSucceeded, userId: (string) $pending->userId, context: [
            'factor' => $providerKey,
        ]);

        if ($usesRecoveryCode) {
            $this->auditor->log(AuditEventType::RecoveryCodeUsed, userId: (string) $pending->userId);
        }

        return $verification;
    }

    private function pendingEnrollment(Authenticatable $user, string $providerKey, string $id): ?FactorEnrollment
    {
        foreach ($this->factors->get($providerKey)->enrollments($user) as $enrollment) {
            if ($id === '' || $enrollment->id === $id) {
                return $enrollment;
            }
        }

        return null;
    }
}
