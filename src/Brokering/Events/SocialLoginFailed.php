<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering\Events;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

/**
 * Shares the auth.login.failed type with the Authentication domain's
 * LoginFailed so sinks see one failed-login stream; the provider is the
 * method, as it is in amr for a successful social login.
 */
final readonly class SocialLoginFailed implements AuditEvent
{
    public const string TYPE = 'auth.login.failed';

    public function __construct(
        public string $provider,
        public string $reason,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: self::TYPE,
            context: [
                'method' => 'social:'.$this->provider,
                'reason' => $this->reason,
            ],
            failure: true,
        );
    }
}
