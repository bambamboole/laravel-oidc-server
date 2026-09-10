<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class TokenIssued implements AuditEvent
{
    public const string TYPE = 'oauth.token.issued';

    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $audiences
     */
    public function __construct(
        public string $grantType,
        public string $jti,
        public array $scopes,
        public ?string $clientId = null,
        public ?string $userId = null,
        public ?string $sid = null,
        public array $audiences = [],
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
                'jti' => $this->jti,
                'scopes' => $this->scopes,
                'audiences' => $this->audiences === [] ? null : $this->audiences,
            ],
        );
    }
}
