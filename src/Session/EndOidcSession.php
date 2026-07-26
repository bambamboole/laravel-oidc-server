<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Session;

use Bambamboole\LaravelOidc\Server\Auth\AuthSessionState;
use Bambamboole\LaravelOidc\Server\BackChannel\BackChannelLogoutNotifier;
use Illuminate\Auth\Events\Logout;

class EndOidcSession
{
    public function __construct(
        private readonly OidcSessionRepository $registry,
        private readonly BackChannelLogoutNotifier $notifier,
        private readonly AuthSessionState $sessionState,
    ) {}

    public function handle(Logout $event): void
    {
        if ($event->guard !== config('passport.guard')) {
            return;
        }

        if (! app()->bound('session.store') || ! app('session.store')->isStarted()) {
            return;
        }

        $sid = $this->sessionState->sid();
        if ($sid === null) {
            return;
        }

        $this->registry->revoke($sid);
        $this->notifier->notify($sid);
    }
}
