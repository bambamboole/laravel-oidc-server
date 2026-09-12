<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Audit;

use DateTimeImmutable;

/**
 * The payload an AuditSink receives. The type is the dispatching event's type,
 * whose value is a dotted string with the category (auth, oauth, admin) as its
 * first segment. Null context values are dropped so sinks only see keys that
 * carry a value.
 */
final readonly class AuditRecord
{
    /** @var array<string, mixed> */
    public array $context;

    /**
     * @param  array<string, mixed>  $context
     */
    public function __construct(
        public \BackedEnum $type,
        public ?string $userId = null,
        public ?string $clientId = null,
        public ?string $sid = null,
        array $context = [],
        public bool $failure = false,
        public ?string $ip = null,
        public ?string $userAgent = null,
        public DateTimeImmutable $occurredAt = new DateTimeImmutable,
    ) {
        $this->context = array_filter($context, static fn (mixed $value): bool => $value !== null);
    }

    public function category(): string
    {
        return explode('.', (string) $this->type->value)[0];
    }

    public function withRequestContext(?string $ip, ?string $userAgent, ?string $sid): self
    {
        return new self(
            type: $this->type,
            userId: $this->userId,
            clientId: $this->clientId,
            sid: $this->sid ?? $sid,
            context: $this->context,
            failure: $this->failure,
            ip: $ip,
            userAgent: $userAgent,
            occurredAt: $this->occurredAt,
        );
    }
}
