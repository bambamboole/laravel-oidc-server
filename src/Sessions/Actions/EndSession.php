<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\Actions;

use Bambamboole\LaravelOidc\Server\Sessions\BackChannel\BackChannelLogoutNotifier;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Session\Session;

/**
 * Ends an SSO session: revokes the OIDC session record, notifies every
 * participating relying party over the back channel, logs the identity
 * guard out and invalidates the browser session.
 */
final class EndSession
{
    public function __construct(
        private readonly OidcSessionRepository $sessions,
        private readonly BackChannelLogoutNotifier $backChannel,
        private readonly AuthFactory $auth,
    ) {}

    public function __invoke(?string $sid, ?Session $session = null): void
    {
        if (is_string($sid) && $sid !== '') {
            $this->sessions->revoke($sid);
            $this->backChannel->notify($sid);
        }

        $this->auth->guard((string) config('oidc.auth.guard', 'identity'))->logout();

        if ($session !== null) {
            $session->invalidate();
            $session->regenerateToken();
        }
    }
}
