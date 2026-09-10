<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\Commands;

use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\Models\SessionParticipant;
use Illuminate\Console\Command;

class PruneSessionsCommand extends Command
{
    protected $signature = 'oidc:prune-sessions';

    protected $description = 'Delete expired OIDC sessions whose back-channel logout notification is older than a day.';

    /**
     * Sessions are deleted only after both expiry and the logout notification
     * have passed a grace window: queued back-channel logout jobs read their
     * session row, and an unnotified session must stay until it is announced.
     */
    public function handle(): int
    {
        $grace = now()->subSeconds(86400);

        $sids = OidcSession::query()
            ->where('expires_at', '<', $grace)
            ->where('logout_notified_at', '<', $grace)
            ->pluck('sid');

        $sessions = OidcSession::query()->whereIn('sid', $sids)->delete();
        SessionParticipant::query()->whereIn('sid', $sids)->delete();

        $this->info("Pruned {$sessions} session(s).");

        return self::SUCCESS;
    }
}
