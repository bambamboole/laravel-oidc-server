<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Keys\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class KeysRotated implements AuditEvent
{
    public const string TYPE = 'admin.keys.rotated';

    public function __construct(public string $kid) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            context: [
                'kid' => $this->kid,
            ],
        );
    }
}
