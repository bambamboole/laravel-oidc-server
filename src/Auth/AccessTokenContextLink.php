<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth;

use Bambamboole\LaravelOidc\Auth\Models\AccessTokenContext;

class AccessTokenContextLink
{
    public function link(string $accessTokenId, string $contextId): void
    {
        $link = new AccessTokenContext;
        $link->access_token_id = $accessTokenId;
        $link->context_id = $contextId;
        $link->created_at = now();
        $link->save();
    }

    public function contextIdFor(string $accessTokenId): ?string
    {
        $contextId = AccessTokenContext::query()
            ->where('access_token_id', $accessTokenId)
            ->value('context_id');

        return is_string($contextId) ? $contextId : null;
    }
}
