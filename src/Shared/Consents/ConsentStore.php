<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Consents;

/**
 * The consents the authorization endpoint consults and records. Both
 * operations are scoped to the current realm; a client is named by its
 * primary key, not the `client_id` it uses on the wire.
 *
 * A consent belongs to a resource as much as to a client. `$resources` are
 * resolved resource identifiers — what `RealmAudiences::resolve()` returns,
 * so a request without an RFC 8707 `resource` carries the realm's issuer
 * rather than an empty list. An empty list covers nothing.
 */
interface ConsentStore
{
    /**
     * Whether the user holds an unrevoked consent for the client that covers
     * every requested scope at every one of the resources.
     *
     * @param  list<string>  $scopes
     * @param  list<string>  $resources
     */
    public function covers(string $userId, string $clientKey, array $scopes, array $resources): bool;

    /**
     * Records an approval: at each resource the scopes are merged into the
     * user's existing consent for the client, and a withdrawn consent becomes
     * active again.
     *
     * @param  list<string>  $scopes
     * @param  list<string>  $resources
     */
    public function grant(string $userId, string $clientKey, array $scopes, array $resources): void;
}
