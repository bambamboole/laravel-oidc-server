<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final class FactorRevoked implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::FactorRevoked; }

    public function __construct(
        public readonly string $userId,
        public readonly string $factor,
        public readonly string $enrollmentId,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            userId: $this->userId,
            context: [
                'factor' => $this->factor,
                'enrollment_id' => $this->enrollmentId,
            ],
        );
    }
}
