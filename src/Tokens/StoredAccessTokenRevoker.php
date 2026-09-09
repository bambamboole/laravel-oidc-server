<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenRevoker;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;

final class StoredAccessTokenRevoker implements AccessTokenRevoker
{
    public function revoke(string $jti): void
    {
        Token::query()->whereKey($jti)->update(['revoked' => true]);
    }
}
