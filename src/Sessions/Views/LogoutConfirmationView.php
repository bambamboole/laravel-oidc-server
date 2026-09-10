<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\Views;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Asks the signed-in user whether to end the session when an RP-initiated
 * logout request carries no verifiable `id_token_hint` (OpenID Connect
 * RP-Initiated Logout 1.0 §6). The page posts `logout_confirmation` back to
 * the end-session endpoint to perform the logout.
 */
interface LogoutConfirmationView
{
    public function respond(LogoutPrompt $prompt, Request $request): Responsable|Response;
}
