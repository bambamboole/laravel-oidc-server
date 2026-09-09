<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

interface AuditSink
{
    public function record(AuditEvent $event): void;
}
