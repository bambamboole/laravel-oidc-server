<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Realms\Settings;

use DateInterval;

final readonly class TokenSettings
{
    /**
     * @param  int  $accessTokenLifetime  seconds
     * @param  int  $idTokenLifetime  seconds
     * @param  int  $clientCredentialsLifetime  seconds
     * @param  int  $refreshTokenLifetime  seconds; the idle cap on a session — a refresh token unused for this long is dead
     * @param  list<string>  $audiences  resource identifiers the realm serves (RFC 9068 §2.2 `aud`): an access token minted without an explicit audience is addressed to them, and the bearer guard accepts a token only when its `aud` names one; empty means the realm issuer URL
     */
    public function __construct(
        public int $accessTokenLifetime = 900,
        public int $idTokenLifetime = 3600,
        public int $clientCredentialsLifetime = 3600,
        public int $refreshTokenLifetime = 1209600,
        public array $audiences = [],
    ) {}

    public static function fromConfig(): self
    {
        return new self(
            accessTokenLifetime: (int) config('oidc.tokens.lifetimes.access_token', 900),
            idTokenLifetime: (int) config('oidc.tokens.lifetimes.id_token', 3600),
            clientCredentialsLifetime: (int) config('oidc.tokens.lifetimes.client_credentials', 3600),
            refreshTokenLifetime: (int) config('oidc.tokens.lifetimes.refresh_token', 1209600),
            audiences: array_values(array_filter((array) config('oidc.tokens.audiences', []), is_string(...))),
        );
    }

    public function accessToken(): DateInterval
    {
        return self::seconds($this->accessTokenLifetime);
    }

    public function clientCredentials(): DateInterval
    {
        return self::seconds($this->clientCredentialsLifetime);
    }

    public function refreshToken(): DateInterval
    {
        return self::seconds($this->refreshTokenLifetime);
    }

    private static function seconds(int $seconds): DateInterval
    {
        return new DateInterval('PT'.max($seconds, 1).'S');
    }
}
