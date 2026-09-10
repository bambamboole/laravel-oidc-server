<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class LoginFailed implements AuditEvent
{
    public const string TYPE = 'auth.login.failed';

    public function __construct(
        public string $method,
        public string $reason,
        public ?string $userId = null,
        public ?string $username = null,
        public ?string $denyReason = null,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            userId: $this->userId,
            context: [
                'method' => $this->method,
                'username' => $this->username,
                'reason' => $this->reason,
                'deny_reason' => $this->denyReason,
            ],
            failure: true,
        );
    }
}
