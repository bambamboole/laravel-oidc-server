<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Testing;

use Bambamboole\LaravelOidc\Server\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Contracts\AuditSink;
use Closure;
use PHPUnit\Framework\Assert;

final class FakeAuditSink implements AuditSink
{
    /** @var list<AuditEvent> */
    private array $events = [];

    public function record(AuditEvent $event): void
    {
        $this->events[] = $event;
    }

    /**
     * @return list<AuditEvent>
     */
    public function events(?AuditEventType $type = null): array
    {
        return array_values(array_filter(
            $this->events,
            static fn (AuditEvent $event): bool => $type === null || $event->type === $type,
        ));
    }

    /**
     * @param  (Closure(AuditEvent): bool)|null  $filter
     */
    public function assertRecorded(AuditEventType $type, ?Closure $filter = null): AuditEvent
    {
        $events = $this->events($type);

        Assert::assertNotEmpty($events, "Expected audit event [{$type->value}] was not recorded.");

        if ($filter === null) {
            return $events[0];
        }

        $matching = array_values(array_filter($events, $filter));

        Assert::assertNotEmpty($matching, "Audit event [{$type->value}] was recorded, but none matched the given filter.");

        return $matching[0];
    }

    public function assertNotRecorded(AuditEventType $type): void
    {
        Assert::assertSame([], $this->events($type), "Unexpected audit event [{$type->value}] was recorded.");
    }

    public function assertNothingRecorded(): void
    {
        Assert::assertSame([], $this->events, 'Expected no audit events, but some were recorded.');
    }
}
