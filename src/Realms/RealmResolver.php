<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

/**
 * The realm the current request belongs to.
 *
 * Bound as a singleton and held by other singletons, so an implementation
 * must derive the realm from the current request on every call rather than
 * remember it — under Octane the same instance serves many requests.
 */
interface RealmResolver
{
    public function current(): Realm;
}
