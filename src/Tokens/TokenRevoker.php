<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenRevoker;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;

/**
 * The only writer of the `revoked` flag. An access token and the refresh token
 * bound to it always go together (RFC 7009 §2.1); a whole authorization-code
 * chain goes when a code is replayed or a rotated-out refresh token is reused
 * (OAuth 2.1 §4.1.3, §4.3.1).
 */
final class TokenRevoker implements AccessTokenRevoker
{
    public function revoke(string $jti): bool
    {
        RefreshToken::query()->where('access_token_id', $jti)->update(['revoked' => true]);

        return AccessToken::query()->whereKey($jti)->where('revoked', false)->update(['revoked' => true]) === 1;
    }

    public function revokeChain(string $authCodeId): void
    {
        $tokens = AccessToken::query()->where('auth_code_id', $authCodeId)->select('id');

        RefreshToken::query()->whereIn('access_token_id', $tokens)->update(['revoked' => true]);
        AccessToken::query()->where('auth_code_id', $authCodeId)->update(['revoked' => true]);
    }
}
