<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\SigningKeys\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final class KeysRotated implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::KeysRotated; }

    public function __construct(public readonly string $kid) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            context: [
                'kid' => $this->kid,
            ],
        );
    }
}
