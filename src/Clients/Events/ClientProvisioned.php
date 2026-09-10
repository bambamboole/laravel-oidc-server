<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class ClientProvisioned implements AuditEvent
{
    public const string TYPE = 'admin.client.provisioned';

    public function __construct(
        public string $clientId,
        public bool $created,
        public bool $secretRotated,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            clientId: $this->clientId,
            context: [
                'created' => $this->created,
                'secret_rotated' => $this->secretRotated,
            ],
        );
    }
}
