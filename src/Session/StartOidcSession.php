<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Session;

use Bambamboole\LaravelOidc\Server\Auth\AuthSessionState;
use Illuminate\Auth\Events\Login;

class StartOidcSession
{
    public function __construct(
        private readonly OidcSessionRepository $registry,
        private readonly AuthSessionState $sessionState,
    ) {}

    public function handle(Login $event): void
    {
        if ($event->guard !== config('passport.guard')) {
            return;
        }

        $sid = $this->registry->start((string) $event->user->getAuthIdentifier());

        if (app()->bound('session.store')) {
            $this->sessionState->startOidcSession($sid);
        }
    }
}
