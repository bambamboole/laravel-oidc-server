<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit\Sinks;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditSink;

final class NullAuditSink implements AuditSink
{
    public function record(AuditRecord $record): void {}
}
