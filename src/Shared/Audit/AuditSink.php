<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Audit;

interface AuditSink
{
    public function record(AuditRecord $record): void;
}
