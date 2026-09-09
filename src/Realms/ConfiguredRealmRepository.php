<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

use Bambamboole\LaravelOidc\Server\Shared\Realms\Realm;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmRepository;

/**
 * Accepts every realm identifier and serves it with the configured
 * settings — realms differ only by their id, as in a deployment that
 * scopes data per tenant but configures all tenants alike.
 */
final class ConfiguredRealmRepository implements RealmRepository
{
    public function find(string $id): ?Realm
    {
        return $id === '' ? null : new ConfiguredRealm($id);
    }
}
