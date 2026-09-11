<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

use Bambamboole\LaravelOidc\Server\Realms\Http\Middleware\ResolveRealm;
use Bambamboole\LaravelOidc\Server\Shared\Context\OidcContext;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\URL;

final class CurrentRealm
{
    /**
     * Serves the callback from the given realm, whatever host the request came
     * in on: everything that resolves the current realm — scoped rows, issuers,
     * signing keys, links to its pages — sees it, and jobs dispatched inside
     * carry it. The realm it interrupted is restored afterwards, so runs nest.
     */
    public static function runAs(string $realm, callable $callback): mixed
    {
        $attributes = request()->attributes;
        $previousAttribute = $attributes->get(ResolveRealm::ATTRIBUTE);
        $previousRealm = OidcContext::realm();
        $previousDefault = URL::getDefaultParameters()['realm'] ?? null;

        $attributes->set(ResolveRealm::ATTRIBUTE, $realm);
        OidcContext::rememberRealm($realm);
        URL::defaults(['realm' => $realm]);

        try {
            return $callback();
        } finally {
            $previousAttribute === null
                ? $attributes->remove(ResolveRealm::ATTRIBUTE)
                : $attributes->set(ResolveRealm::ATTRIBUTE, $previousAttribute);
            $previousRealm === null ? Context::forget(OidcContext::REALM) : OidcContext::rememberRealm($previousRealm);
            URL::defaults(['realm' => $previousDefault]);
        }
    }
}
