<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Session;

/**
 * Names the single guard that owns the first-party session token. The mint
 * provider and the Login/Logout listeners must all resolve the guard through
 * here — a login on any other guard (e.g. an admin panel) must neither mint,
 * overwrite, nor revoke the token.
 */
final class SessionTokenGuard
{
    public static function name(): ?string
    {
        $guard = config('oidc.session_token.guard')
            ?? config('oidc.auth.guard')
            ?? config('auth.defaults.guard');

        return is_string($guard) && $guard !== '' ? $guard : null;
    }
}
