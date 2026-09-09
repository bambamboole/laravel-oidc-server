<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

/**
 * Single-realm default: every request belongs to the configured realm.
 */
final readonly class ConfiguredRealmResolver implements RealmResolver
{
    public function __construct(private RealmRepository $realms) {}

    public function current(): Realm
    {
        $id = (string) config('oidc.realm', 'default');

        return $this->realms->find($id !== '' ? $id : 'default') ?? new ConfiguredRealm($id !== '' ? $id : 'default');
    }
}
