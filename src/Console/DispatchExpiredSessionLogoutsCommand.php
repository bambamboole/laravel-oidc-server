<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Console;

use Bambamboole\LaravelOidc\Auth\Models\OidcSession;
use Bambamboole\LaravelOidc\BackChannel\BackChannelLogoutNotifier;
use Illuminate\Console\Command;

class DispatchExpiredSessionLogoutsCommand extends Command
{
    protected $signature = 'oidc:dispatch-expired-session-logouts';

    protected $description = 'Send back-channel logout to participants of sessions that hit their absolute lifetime.';

    public function handle(BackChannelLogoutNotifier $notifier): int
    {
        $count = 0;

        OidcSession::query()
            ->where('expires_at', '<', now())
            ->whereNull('revoked_at')
            ->whereNull('logout_notified_at')
            ->eachById(function (OidcSession $session) use ($notifier, &$count): void {
                $notifier->notify($session->sid);
                $count++;
            });

        $this->info("Dispatched logout for {$count} expired session(s).");

        return self::SUCCESS;
    }
}
