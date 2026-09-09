<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Context;

use Bambamboole\LaravelOidc\Server\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\SessionParticipant;
use Bambamboole\LaravelOidc\Server\Tokens\Context\AccessTokenContext;
use Illuminate\Console\Command;

class PruneAuthenticationContextsCommand extends Command
{
    protected $signature = 'oidc:prune-authentication-contexts';

    protected $description = 'Delete expired OIDC authentication contexts, stale access-token links, and stale notified sessions.';

    public function handle(): int
    {
        $contexts = AuthenticationContext::query()->where('expires_at', '<', now())->delete();

        // Link rows outlive their context so refresh can distinguish "expired" from "never linked".
        // Retain them until no live refresh token could reference them: absolute + refresh idle window.
        $realm = app(RealmResolver::class)->current();
        $horizon = now()->subSeconds($realm->sessions()->absoluteLifetime + $realm->tokens()->refreshTokenLifetime);
        $links = AccessTokenContext::query()->where('created_at', '<', $horizon)->delete();

        // Sessions are deleted only after both expiry and logout notification grace windows.
        // The second grace window lets queued back-channel logout jobs read their session.
        $sessionGrace = now()->subSeconds(86400);
        $sessions = OidcSession::query()
            ->where('expires_at', '<', $sessionGrace)
            ->where('logout_notified_at', '<', $sessionGrace)
            ->pluck('sid');
        $sessionCount = OidcSession::query()->whereIn('sid', $sessions)->delete();
        SessionParticipant::query()->whereIn('sid', $sessions)->delete();

        $this->info("Pruned {$contexts} context(s), {$links} link(s), and {$sessionCount} session(s).");

        return self::SUCCESS;
    }
}
