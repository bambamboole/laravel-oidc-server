<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Session;

use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Bambamboole\LaravelOidc\BackChannel\BackChannelLogoutNotifier;
use Illuminate\Auth\Events\Logout;

class EndOidcSession
{
    public function __construct(
        private readonly SessionRegistry $registry,
        private readonly BackChannelLogoutNotifier $notifier,
    ) {}

    public function handle(Logout $event): void
    {
        if ($event->guard !== config('passport.guard')) {
            return;
        }

        if (! app()->bound('session.store') || ! app('session.store')->isStarted()) {
            return;
        }

        $sid = session()->get('oidc.sid');
        if (! is_string($sid) || $sid === '') {
            return;
        }

        $this->registry->revoke($sid);
        $this->notifier->notify($sid);
    }
}
