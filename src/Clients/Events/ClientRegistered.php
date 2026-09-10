<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

final readonly class ClientRegistered implements AuditEvent
{
    public const string TYPE = 'admin.client.registered';

    /**
     * @param  list<string>  $redirectUris
     */
    public function __construct(
        public string $clientId,
        public string $name,
        public array $redirectUris,
        public string $tokenEndpointAuthMethod,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            clientId: $this->clientId,
            context: [
                'client_name' => $this->name,
                'redirect_uris' => $this->redirectUris,
                'token_endpoint_auth_method' => $this->tokenEndpointAuthMethod,
            ],
        );
    }
}
