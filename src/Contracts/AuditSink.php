<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Contracts;

use Bambamboole\LaravelOidc\Server\Audit\AuditEvent;

interface AuditSink
{
    public function record(AuditEvent $event): void;
}
