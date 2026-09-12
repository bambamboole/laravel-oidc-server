<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Listeners;

use Bambamboole\LaravelOidc\Server\Authentication\Events\LoggedOut;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\IdentityGuard;
use Illuminate\Auth\Events\Logout;

final readonly class DispatchLoggedOut
{
    public function handle(Logout $event): void
    {
        if ($event->guard !== IdentityGuard::name() || $event->user === null) {
            return;
        }

        event(new LoggedOut((string) $event->user->getAuthIdentifier()));
    }
}
