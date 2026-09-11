<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

/**
 * Shares the auth.login.failed type with the Authentication domain's
 * LoginFailed so sinks see one failed-login stream; the provider is the
 * method, as it is in amr for a successful social login.
 */
final class SocialLoginFailed implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::LoginFailed; }

    public function __construct(
        public readonly string $provider,
        public readonly string $reason,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            context: [
                'method' => 'social:'.$this->provider,
                'reason' => $this->reason,
            ],
            failure: true,
        );
    }
}
