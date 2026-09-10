<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Consents\Models\Consent;
use Bambamboole\LaravelOidc\Server\Shared\Consents\ConsentStore;
use Illuminate\Support\Facades\Date;

/**
 * Consents persist independently of the tokens they led to: a token expiring
 * or being revoked leaves the consent in place, and only `revoke()` withdraws
 * it. Every lookup is scoped to the current realm.
 */
class ConsentRepository implements ConsentStore
{
    public function find(string $userId, Client $client): ?Consent
    {
        return $this->findByKey($userId, (string) $client->getKey());
    }

    public function covers(string $userId, string $clientKey, array $scopes): bool
    {
        return $this->findByKey($userId, $clientKey)?->covers($scopes) ?? false;
    }

    public function grant(string $userId, string $clientKey, array $scopes): void
    {
        $consent = $this->findByKey($userId, $clientKey) ?? new Consent([
            'realm_id' => Consent::currentRealm(),
            'user_id' => $userId,
            'client_id' => $clientKey,
            'scopes' => [],
        ]);

        $consent->forceFill([
            'scopes' => array_values(array_unique([...$consent->scopes, ...$scopes])),
            'granted_at' => Date::now(),
            'revoked_at' => null,
        ])->save();
    }

    public function revoke(string $userId, Client $client): void
    {
        Consent::query()
            ->inRealm()
            ->where('user_id', $userId)
            ->where('client_id', $client->getKey())
            ->whereNull('revoked_at')
            ->update(['revoked_at' => Date::now()]);
    }

    private function findByKey(string $userId, string $clientKey): ?Consent
    {
        return Consent::query()
            ->inRealm()
            ->where('user_id', $userId)
            ->where('client_id', $clientKey)
            ->first();
    }
}
