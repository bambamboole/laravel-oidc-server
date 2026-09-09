<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Tokens;

interface AccessTokenRevoker
{
    /** Revokes the access token with the given jti; a no-op for unknown ids. */
    public function revoke(string $jti): void;
}
