<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Grants;

use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;

/**
 * Every access token minted from an authorization code, directly or through
 * refresh rotation, records the code. A replayed code or a reused refresh
 * token is a sign the chain leaked, so the whole chain is revoked
 * (OAuth 2.1 §4.1.3 and §4.3.1).
 */
final class TokenLineage
{
    public function revoke(string $authCodeId): void
    {
        $tokens = Token::query()->where('auth_code_id', $authCodeId)->select('id');

        RefreshToken::query()->whereIn('access_token_id', $tokens)->update(['revoked' => true]);
        Token::query()->where('auth_code_id', $authCodeId)->update(['revoked' => true]);
    }
}
