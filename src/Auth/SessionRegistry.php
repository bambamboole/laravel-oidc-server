<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth;

use Bambamboole\LaravelOidc\Auth\Models\OidcSession;
use Bambamboole\LaravelOidc\Auth\Models\SessionParticipant;
use DateInterval;

class SessionRegistry
{
    public function start(string $userId): string
    {
        $session = new OidcSession;
        $session->user_id = $userId;
        $session->created_at = now();
        $session->expires_at = now()->add(
            new DateInterval('PT'.(int) config('oidc.session.absolute_lifetime').'S'),
        );
        $session->save();

        return $session->sid;
    }

    public function find(string $sid): ?OidcSession
    {
        return OidcSession::query()->find($sid);
    }

    public function recordParticipant(string $sid, string $clientId): void
    {
        SessionParticipant::query()->updateOrInsert(
            ['sid' => $sid, 'client_id' => $clientId],
            ['created_at' => now()],
        );
    }

    /** @return array<int, string> */
    public function participantClientIds(string $sid): array
    {
        return SessionParticipant::query()->where('sid', $sid)->pluck('client_id')->all();
    }

    public function revoke(string $sid): void
    {
        OidcSession::query()->whereKey($sid)->whereNull('revoked_at')->update(['revoked_at' => now()]);
    }

    public function markNotified(string $sid): void
    {
        OidcSession::query()->whereKey($sid)->update(['logout_notified_at' => now()]);
    }
}
