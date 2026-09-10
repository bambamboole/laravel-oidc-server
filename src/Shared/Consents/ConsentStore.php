<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Consents;

/**
 * The consents the authorization endpoint consults and records. Both
 * operations are scoped to the current realm; a client is named by its
 * primary key, not the `client_id` it uses on the wire.
 */
interface ConsentStore
{
    /**
     * Whether the user holds an unrevoked consent for the client that covers
     * every requested scope.
     *
     * @param  list<string>  $scopes
     */
    public function covers(string $userId, string $clientKey, array $scopes): bool;

    /**
     * Records an approval: the scopes are merged into the user's existing
     * consent for the client, and a withdrawn consent becomes active again.
     *
     * @param  list<string>  $scopes
     */
    public function grant(string $userId, string $clientKey, array $scopes): void;
}
