<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class ConsentApproved implements AuditEvent
{
    public const string TYPE = 'oauth.consent.approved';

    /**
     * @param  list<string>  $scopes
     */
    public function __construct(
        public array $scopes,
        public ?string $userId = null,
        public ?string $clientId = null,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            userId: $this->userId,
            clientId: $this->clientId,
            context: [
                'scopes' => $this->scopes,
            ],
        );
    }
}
