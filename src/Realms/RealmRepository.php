<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

/**
 * Looks a realm up by the identifier in the request path. An application
 * with a realm model binds its own implementation; an unknown identifier
 * returns null and the request answers 404.
 */
interface RealmRepository
{
    public function find(string $id): ?Realm;
}
