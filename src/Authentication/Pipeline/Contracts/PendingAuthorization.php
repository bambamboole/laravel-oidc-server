<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Pipeline\Contracts;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Illuminate\Http\Request;

/**
 * The authorization request an interactive login was initiated from, if any,
 * so the post-login pipeline can see the pending client and scopes without
 * knowing how the authorize endpoint stashed them.
 */
interface PendingAuthorization
{
    public function client(Request $request): ?Client;

    /** @return list<string> */
    public function scopes(Request $request): array;
}
