<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final class ClientRegistered implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::ClientRegistered; }

    /**
     * @param  list<string>  $redirectUris
     */
    public function __construct(
        public readonly string $clientId,
        public readonly string $name,
        public readonly array $redirectUris,
        public readonly string $tokenEndpointAuthMethod,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            clientId: $this->clientId,
            context: [
                'client_name' => $this->name,
                'redirect_uris' => $this->redirectUris,
                'token_endpoint_auth_method' => $this->tokenEndpointAuthMethod,
            ],
        );
    }
}
