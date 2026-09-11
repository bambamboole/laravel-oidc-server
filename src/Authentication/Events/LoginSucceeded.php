<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final class LoginSucceeded implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::LoginSucceeded; }

    /**
     * @param  list<string>  $amr
     */
    public function __construct(
        public readonly string $userId,
        public readonly array $amr,
        public readonly bool $remember = false,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            userId: $this->userId,
            context: [
                'amr' => $this->amr === [] ? null : $this->amr,
                'remember' => $this->remember ?: null,
            ],
        );
    }
}
