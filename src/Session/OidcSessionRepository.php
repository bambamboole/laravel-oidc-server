<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Session;

use Bambamboole\LaravelOidc\Server\Auth\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Auth\Models\SessionParticipant;
use DateInterval;

class OidcSessionRepository
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

    /**
     * createOrFirst (not updateOrInsert) so the model's creating hook runs —
     * it generates the uuid key — while the unique (sid, client_id) index
     * still absorbs concurrent inserts.
     */
    public function recordParticipant(string $sid, string $clientId): void
    {
        SessionParticipant::query()->createOrFirst(
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
