<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class FactorConfirmed implements AuditEvent
{
    public const string TYPE = 'auth.mfa.factor_confirmed';

    public function __construct(
        public string $userId,
        public string $factor,
        public string $enrollmentId,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            userId: $this->userId,
            context: [
                'factor' => $this->factor,
                'enrollment_id' => $this->enrollmentId,
            ],
        );
    }
}
