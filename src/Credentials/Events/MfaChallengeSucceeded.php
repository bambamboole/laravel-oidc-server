<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class MfaChallengeSucceeded implements AuditEvent
{
    public const string TYPE = 'auth.mfa.challenge_succeeded';

    public function __construct(
        public string $userId,
        public string $factor,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            userId: $this->userId,
            context: [
                'factor' => $this->factor,
            ],
        );
    }
}
