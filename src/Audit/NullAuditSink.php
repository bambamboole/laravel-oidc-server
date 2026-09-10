<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditSink;

final class NullAuditSink implements AuditSink
{
    public function record(AuditEvent $event): void {}
}
