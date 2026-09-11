<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final class MfaChallengeSucceeded implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::MfaChallengeSucceeded; }

    public function __construct(
        public readonly string $userId,
        public readonly string $factor,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            userId: $this->userId,
            context: [
                'factor' => $this->factor,
            ],
        );
    }
}
