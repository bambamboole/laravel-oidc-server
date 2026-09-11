<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Consents\Models\Consent;
use Bambamboole\LaravelOidc\Server\Shared\Consents\ConsentStore;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Date;

/**
 * Consents persist independently of the tokens they led to: a token expiring
 * or being revoked leaves the consent in place, and only `revoke()` withdraws
 * it. Every lookup is scoped to the current realm.
 */
class ConsentRepository implements ConsentStore
{
    public function find(string $userId, Client $client, string $resource): ?Consent
    {
        return $this->findByKey($userId, (string) $client->getKey(), $resource);
    }

    /**
     * Every resource the user has a consent for with this client, withdrawn
     * ones included — what an account screen lists.
     *
     * @return Collection<int, Consent>
     */
    public function forClient(string $userId, Client $client): Collection
    {
        return Consent::query()
            ->inRealm()
            ->where('user_id', $userId)
            ->where('client_id', $client->getKey())
            ->orderBy('resource')
            ->get();
    }

    public function covers(string $userId, string $clientKey, array $scopes, array $resources): bool
    {
        if ($resources === []) {
            return false;
        }

        return array_all($resources, fn (string $resource): bool => $this->findByKey($userId, $clientKey, $resource)?->covers($scopes) ?? false);
    }

    public function grant(string $userId, string $clientKey, array $scopes, array $resources): void
    {
        foreach ($resources as $resource) {
            $consent = $this->findByKey($userId, $clientKey, $resource) ?? new Consent([
                'realm_id' => Consent::currentRealm(),
                'user_id' => $userId,
                'client_id' => $clientKey,
                'resource' => $resource,
                'scopes' => [],
            ]);

            $consent->forceFill([
                'scopes' => array_values(array_unique([...$consent->scopes, ...$scopes])),
                'granted_at' => Date::now(),
                'revoked_at' => null,
            ])->save();
        }
    }

    /** Withdraws the client's consent at every resource, or at one of them. */
    public function revoke(string $userId, Client $client, ?string $resource = null): void
    {
        Consent::query()
            ->inRealm()
            ->where('user_id', $userId)
            ->where('client_id', $client->getKey())
            ->when($resource !== null, fn ($query) => $query->where('resource', $resource))
            ->whereNull('revoked_at')
            ->update(['revoked_at' => Date::now()]);
    }

    private function findByKey(string $userId, string $clientKey, string $resource): ?Consent
    {
        return Consent::query()
            ->inRealm()
            ->where('user_id', $userId)
            ->where('client_id', $clientKey)
            ->where('resource', $resource)
            ->first();
    }
}
