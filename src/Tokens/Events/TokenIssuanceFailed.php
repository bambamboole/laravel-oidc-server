<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class TokenIssuanceFailed implements AuditEvent
{
    public const string TYPE = 'oauth.token.failed';

    public function __construct(
        public string $grantType,
        public string $reason,
        public ?string $clientId = null,
        public ?string $userId = null,
        public ?string $sid = null,
        public ?string $denyReason = null,
        public ?string $scope = null,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            userId: $this->userId,
            clientId: $this->clientId,
            sid: $this->sid,
            context: [
                'grant_type' => $this->grantType,
                'reason' => $this->reason,
                'deny_reason' => $this->denyReason,
                'scope' => $this->scope,
            ],
            failure: true,
        );
    }
}
