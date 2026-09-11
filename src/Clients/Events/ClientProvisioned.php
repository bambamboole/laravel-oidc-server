<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final class ClientProvisioned implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::ClientProvisioned; }

    public function __construct(
        public readonly string $clientId,
        public readonly bool $created,
        public readonly bool $secretRotated,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            clientId: $this->clientId,
            context: [
                'created' => $this->created,
                'secret_rotated' => $this->secretRotated,
            ],
        );
    }
}
