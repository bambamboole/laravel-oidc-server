<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\Listeners;

use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\IdentityGuard;
use Illuminate\Auth\Events\Login;

class StartOidcSession
{
    public function __construct(
        private readonly OidcSessionRepository $registry,
        private readonly AuthSessionState $sessionState,
    ) {}

    public function handle(Login $event): void
    {
        if ($event->guard !== IdentityGuard::name()) {
            return;
        }

        $browserSession = app()->bound('session.store') ? app('session.store') : null;

        $sid = $this->registry->start(
            (string) $event->user->getAuthIdentifier(),
            $browserSession?->isStarted() ? $browserSession->getId() : null,
        );

        if ($browserSession !== null) {
            $this->sessionState->startOidcSession($sid);
        }
    }
}
