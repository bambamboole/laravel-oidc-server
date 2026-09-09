<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Audit;

/**
 * Records a security-relevant event. Recording is fail-open: an implementation
 * must never let a broken sink take down the auth or token flow that called it.
 */
interface Auditor
{
    /**
     * @param  array<string, mixed>  $context
     */
    public function log(
        AuditEventType $type,
        ?string $userId = null,
        ?string $clientId = null,
        ?string $sid = null,
        array $context = [],
    ): void;
}
