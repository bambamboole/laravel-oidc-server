<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Protocol;

use Illuminate\Http\Request;

/**
 * Completes the authorization request the consent screen was rendered for,
 * with the user's decision. The response is the redirect back to the client:
 * the code on approval, the OAuth error on denial.
 */
interface AuthorizationCompleter
{
    public function complete(Request $request, bool $approved): CompletedAuthorization;
}
