<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final class TokenRevoked implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::TokenRevoked; }

    public function __construct(
        public readonly string $clientId,
        public readonly string $tokenType,
        public readonly ?string $jti = null,
        public readonly ?string $refreshTokenJti = null,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            clientId: $this->clientId,
            context: [
                'token_type' => $this->tokenType,
                'refresh_token_jti' => $this->refreshTokenJti,
                'jti' => $this->jti,
            ],
        );
    }
}
