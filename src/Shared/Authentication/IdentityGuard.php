<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Authentication;

/**
 * Names the guard the package authenticates against. Deployment-wide: a realm
 * cannot override it.
 *
 * Every surface that needs the name resolves it here — providers, the route
 * file, controllers, and the listeners that gate on an event's guard — so the
 * fallback is spelled once rather than re-typed at each call site.
 */
final class IdentityGuard
{
    public static function name(): string
    {
        return (string) config('oidc.auth.guard', 'identity');
    }
}
