<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class TokenRevoked implements AuditEvent
{
    public const string TYPE = 'oauth.token.revoked';

    public function __construct(
        public string $clientId,
        public string $tokenType,
        public ?string $jti = null,
        public ?string $refreshTokenJti = null,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            clientId: $this->clientId,
            context: [
                'token_type' => $this->tokenType,
                'refresh_token_jti' => $this->refreshTokenJti,
                'jti' => $this->jti,
            ],
        );
    }
}
