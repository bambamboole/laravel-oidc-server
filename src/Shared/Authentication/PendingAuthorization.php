<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Authentication;

use Illuminate\Http\Request;

/**
 * The authorization request an interactive login was initiated from, if any,
 * so the post-login pipeline can see the pending client and scopes without
 * knowing how the authorize endpoint stashed them.
 */
interface PendingAuthorization
{
    /** The `client_id` of the pending authorization request. */
    public function clientId(Request $request): ?string;

    /** @return list<string> */
    public function scopes(Request $request): array;
}
