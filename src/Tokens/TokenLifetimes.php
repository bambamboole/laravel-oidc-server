<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use DateInterval;

/**
 * The single place token TTLs come from. Per-client overrides and, later,
 * per-realm defaults resolve through here rather than at each call site.
 */
final class TokenLifetimes
{
    public function accessToken(): DateInterval
    {
        return $this->seconds((int) config('oidc.token_lifetimes.access_token', 900));
    }

    public function idTokenSeconds(): int
    {
        return (int) config('oidc.token_lifetimes.id_token', 3600);
    }

    public function clientCredentials(): DateInterval
    {
        return $this->seconds((int) config('oidc.token_lifetimes.client_credentials', 3600));
    }

    /** The idle cap on a session: a refresh token unused for this long is dead. */
    public function refreshToken(): DateInterval
    {
        return $this->seconds((int) config('oidc.token_lifetimes.refresh_token', 1209600));
    }

    private function seconds(int $seconds): DateInterval
    {
        return new DateInterval('PT'.max($seconds, 1).'S');
    }
}
