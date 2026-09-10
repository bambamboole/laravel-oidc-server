<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Lcobucci\JWT\Token\Plain;

/**
 * What a `token` value handed to the introspection or revocation endpoint
 * resolved to (RFC 7662 §2.1, RFC 7009 §2.1). Either kind comes with the
 * access token record that carries the client, user, scopes and realm: for
 * a presented access token that is the record itself, next to its verified
 * JWT; for a presented refresh token it is the one it was issued alongside.
 */
final readonly class PresentedToken
{
    private function __construct(
        public AccessToken $accessToken,
        public ?Plain $jwt,
        public ?RefreshToken $refreshToken,
    ) {}

    public static function accessToken(Plain $jwt, AccessToken $accessToken): self
    {
        return new self($accessToken, $jwt, null);
    }

    public static function refreshToken(RefreshToken $refreshToken, AccessToken $accessToken): self
    {
        return new self($accessToken, null, $refreshToken);
    }

    public function isRefreshToken(): bool
    {
        return $this->refreshToken instanceof RefreshToken;
    }
}
