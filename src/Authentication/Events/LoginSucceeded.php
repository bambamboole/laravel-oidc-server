<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class LoginSucceeded implements AuditEvent
{
    public const string TYPE = 'auth.login.succeeded';

    /**
     * @param  list<string>  $amr
     */
    public function __construct(
        public string $userId,
        public array $amr,
        public bool $remember = false,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            userId: $this->userId,
            context: [
                'amr' => $this->amr === [] ? null : $this->amr,
                'remember' => $this->remember ?: null,
            ],
        );
    }
}
