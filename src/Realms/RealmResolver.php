<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

/**
 * The realm the current request belongs to. The package stores this identifier
 * on its own rows and scopes every lookup by it; what a realm *is* — its name,
 * branding, administrators — belongs to the application.
 *
 * Bound as a scoped binding. Anything longer-lived than a request (a singleton
 * such as the signing key store) must call this per use rather than hold it.
 */
interface RealmResolver
{
    public function current(): string;
}
