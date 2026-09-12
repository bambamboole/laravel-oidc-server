<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Audit;

/**
 * A domain event that is also security-relevant. Dispatching it through the
 * event dispatcher is all a domain does; the Audit domain listens for this
 * contract, enriches the record with request context and hands it to the
 * configured sink. The type is a backed enum: the package raises
 * AuditEventType, a host app extends the audit trail with its own enum.
 */
interface AuditEvent
{
    public \BackedEnum $type { get; }

    public function auditRecord(): AuditRecord;
}
