<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class ClientAuthenticationFailed implements AuditEvent
{
    public const string TYPE = 'oauth.client_auth.failed';

    public function __construct(
        public string $endpoint,
        public string $reason,
        public ?string $clientId = null,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            clientId: $this->clientId,
            context: [
                'endpoint' => $this->endpoint,
                'reason' => $this->reason,
            ],
            failure: true,
        );
    }
}
