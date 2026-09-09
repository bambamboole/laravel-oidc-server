<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering\Contracts;

use Bambamboole\LaravelOidc\Server\Brokering\PendingAuthorization;
use Bambamboole\LaravelOidc\Server\Brokering\SocialAuthenticationException;
use Bambamboole\LaravelOidc\Server\Brokering\SocialUser;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface SocialProvider
{
    public function key(): string;

    /**
     * Build the upstream authorize redirect and remember state/PKCE/nonce in
     * the session.
     */
    public function redirect(Request $request, string $intent = PendingAuthorization::INTENT_LOGIN): Response;

    /**
     * Validate the callback against the pending authorization and exchange the
     * code for the upstream identity.
     *
     * @throws SocialAuthenticationException
     */
    public function user(Request $request, PendingAuthorization $pending): SocialUser;
}
