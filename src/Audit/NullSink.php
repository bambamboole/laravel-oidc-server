<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

final class NullSink implements AuditSink
{
    public function record(AuditEvent $event): void {}
}
