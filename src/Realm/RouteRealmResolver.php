<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realm;

/**
 * Derives the realm from the request: from the attribute ResolveRealm sets, or
 * from the `{realm}` route parameter before it has run. Console commands,
 * queue jobs and anything else outside a matched route fall back to the
 * configured realm.
 */
final readonly class RouteRealmResolver implements RealmResolver
{
    public function __construct(private RealmResolver $fallback) {}

    public function current(): string
    {
        $request = request();
        $realm = $request->attributes->get(ResolveRealm::ATTRIBUTE) ?? $request->route('realm');

        return is_string($realm) && $realm !== '' ? $realm : $this->fallback->current();
    }
}
