<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\Actions;

use Bambamboole\LaravelOidc\Server\Sessions\EndOidcSession;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Session\Session;

/**
 * Ends the browser's login: logs the identity guard out and invalidates the
 * session. Revoking the OIDC session and notifying its relying parties over
 * the back channel belongs to the Logout listener ({@see EndOidcSession}),
 * so every logout path — this action or the application's own — does that
 * work exactly once.
 */
final readonly class EndSession
{
    public function __construct(private AuthFactory $auth) {}

    public function __invoke(?Session $session = null): void
    {
        $this->auth->guard((string) config('oidc.auth.guard', 'identity'))->logout();

        if ($session instanceof Session) {
            $session->invalidate();
            $session->regenerateToken();
        }
    }
}
