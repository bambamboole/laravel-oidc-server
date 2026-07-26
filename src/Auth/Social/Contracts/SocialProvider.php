<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Social\Contracts;

use Bambamboole\LaravelOidc\Server\Auth\Social\PendingAuthorization;
use Bambamboole\LaravelOidc\Server\Auth\Social\SocialAuthenticationException;
use Bambamboole\LaravelOidc\Server\Auth\Social\SocialUser;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

interface SocialProvider
{
    public function key(): string;

    /**
     * Build the upstream authorize redirect and remember state/PKCE/nonce in
     * the session.
     */
    public function redirect(Request $request, string $intent = PendingAuthorization::INTENT_LOGIN): RedirectResponse;

    /**
     * Validate the callback against the pending authorization and exchange the
     * code for the upstream identity.
     *
     * @throws SocialAuthenticationException
     */
    public function user(Request $request, PendingAuthorization $pending): SocialUser;
}
