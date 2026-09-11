<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Testing;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditSink;
use Closure;
use PHPUnit\Framework\Assert;

final class FakeAuditSink implements AuditSink
{
    /** @var list<AuditRecord> */
    private array $records = [];

    public function record(AuditRecord $record): void
    {
        $this->records[] = $record;
    }

    /**
     * @return list<AuditRecord>
     */
    public function records(string|\BackedEnum|null $type = null): array
    {
        $type = $this->value($type);

        return array_values(array_filter(
            $this->records,
            static fn (AuditRecord $record): bool => $type === null || $record->type === $type,
        ));
    }

    /**
     * @param  (Closure(AuditRecord): bool)|null  $filter
     */
    public function assertRecorded(string|\BackedEnum $type, ?Closure $filter = null): AuditRecord
    {
        $records = $this->records($type);
        $type = $this->value($type);

        Assert::assertNotEmpty($records, "Expected audit record [{$type}] was not recorded.");

        if (! $filter instanceof Closure) {
            return $records[0];
        }

        $matching = array_values(array_filter($records, $filter));

        Assert::assertNotEmpty($matching, "Audit record [{$type}] was recorded, but none matched the given filter.");

        return $matching[0];
    }

    public function assertNotRecorded(string|\BackedEnum $type): void
    {
        $records = $this->records($type);
        $type = $this->value($type);

        Assert::assertSame([], $records, "Unexpected audit record [{$type}] was recorded.");
    }

    public function assertNothingRecorded(): void
    {
        Assert::assertSame([], $this->records, 'Expected no audit records, but some were recorded.');
    }

    private function value(string|\BackedEnum|null $type): ?string
    {
        return $type instanceof \BackedEnum ? (string) $type->value : $type;
    }
}
