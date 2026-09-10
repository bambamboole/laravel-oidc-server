<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class UserRegistered implements AuditEvent
{
    public const string TYPE = 'auth.registration.succeeded';

    public function __construct(public string $userId) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            userId: $this->userId,
        );
    }
}
