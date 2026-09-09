<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realm;

/**
 * Single-realm default: every request belongs to the configured realm. An
 * application serving several realms binds a resolver that derives it from the
 * request instead.
 */
final class ConfiguredRealmResolver implements RealmResolver
{
    public function current(): string
    {
        $realm = (string) config('oidc.realm', 'default');

        return $realm !== '' ? $realm : 'default';
    }
}
