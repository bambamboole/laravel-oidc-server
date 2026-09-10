<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class RecoveryCodeUsed implements AuditEvent
{
    public const string TYPE = 'auth.mfa.recovery_code_used';

    public function __construct(public string $userId) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            userId: $this->userId,
        );
    }
}
