<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

use DateTimeImmutable;

final readonly class AuditEvent
{
    /**
     * @param  array<string, mixed>  $context
     */
    public function __construct(
        public AuditEventType $type,
        public ?string $userId,
        public ?string $clientId,
        public ?string $sid,
        public ?string $ip,
        public ?string $userAgent,
        public DateTimeImmutable $occurredAt,
        public array $context = [],
    ) {}
}
