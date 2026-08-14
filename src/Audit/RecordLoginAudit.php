<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

use Bambamboole\LaravelOidc\Server\Auth\AuthSessionState;
use Illuminate\Auth\Events\Login;

class RecordLoginAudit
{
    public function __construct(
        private readonly Auditor $auditor,
        private readonly AuthSessionState $sessionState,
    ) {}

    public function handle(Login $event): void
    {
        if ($event->guard !== config('passport.guard')) {
            return;
        }

        $amr = app()->bound('session.store') && app('session.store')->isStarted()
            ? $this->sessionState->amr()
            : [];

        $this->auditor->log(
            AuditEventType::LoginSucceeded,
            userId: (string) $event->user->getAuthIdentifier(),
            context: array_filter([
                'amr' => $amr,
                'remember' => $event->remember,
            ], static fn (mixed $value): bool => $value !== [] && $value !== false),
        );
    }
}
