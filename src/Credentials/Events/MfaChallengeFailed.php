<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class MfaChallengeFailed implements AuditEvent
{
    public const string TYPE = 'auth.mfa.challenge_failed';

    public function __construct(
        public string $userId,
        public string $factor,
        public string $reason,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            userId: $this->userId,
            context: [
                'factor' => $this->factor,
                'reason' => $this->reason,
            ],
            failure: true,
        );
    }
}
