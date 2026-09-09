<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions;

use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;

class OidcSessionRepository
{
    public function __construct(private readonly RealmResolver $realms) {}

    public function start(string $userId): string
    {
        $session = new OidcSession;
        $session->realm_id = OidcSession::currentRealm();
        $session->user_id = $userId;
        $session->created_at = now();
        $session->expires_at = now()->add($this->realms->current()->sessions()->absolute());
        $session->save();

        return $session->sid;
    }

    public function find(string $sid): ?OidcSession
    {
        return OidcSession::query()->inRealm()->find($sid);
    }

    /**
     * createOrFirst (not updateOrInsert) so the model's creating hook runs —
     * it generates the uuid key — while the unique (sid, client_id) index
     * still absorbs concurrent inserts.
     */
    /** @param  string  $clientKey  the client's primary key */
    public function recordParticipant(string $sid, string $clientKey): void
    {
        SessionParticipant::query()->createOrFirst(
            ['sid' => $sid, 'client_id' => $clientKey],
            ['created_at' => now()],
        );
    }

    /** @return array<int, string> the participating clients' primary keys */
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
