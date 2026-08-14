<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

use Illuminate\Auth\Events\Logout;

class RecordLogoutAudit
{
    public function __construct(private readonly Auditor $auditor) {}

    public function handle(Logout $event): void
    {
        if ($event->guard !== config('passport.guard') || $event->user === null) {
            return;
        }

        $this->auditor->log(
            AuditEventType::Logout,
            userId: (string) $event->user->getAuthIdentifier(),
        );
    }
}
