<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenRevoker;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Illuminate\Support\Facades\Date;

/**
 * The only writer of `revoked_at`. An access token and the refresh token
 * bound to it always go together (RFC 7009 §2.1); a whole authorization-code
 * chain goes when a code is replayed or a rotated-out refresh token is reused
 * (OAuth 2.1 §4.1.3, §4.3.1).
 */
final class TokenRevoker implements AccessTokenRevoker
{
    public function revoke(string $jti): bool
    {
        $now = Date::now();

        RefreshToken::query()->where('access_token_id', $jti)->whereNull('revoked_at')->update(['revoked_at' => $now]);

        return AccessToken::query()->whereKey($jti)->whereNull('revoked_at')->update(['revoked_at' => $now]) === 1;
    }

    /** @param  string  $authCodeId  the id of the authorization code the chain descends from, which may already be purged */
    public function revokeChain(string $authCodeId): void
    {
        $now = Date::now();
        $tokens = AccessToken::query()->where('auth_code_id', $authCodeId)->select('id');

        RefreshToken::query()->whereIn('access_token_id', $tokens)->whereNull('revoked_at')->update(['revoked_at' => $now]);
        AccessToken::query()->where('auth_code_id', $authCodeId)->whereNull('revoked_at')->update(['revoked_at' => $now]);
    }
}
