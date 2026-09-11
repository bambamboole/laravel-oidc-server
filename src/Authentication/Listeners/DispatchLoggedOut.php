<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Listeners;

use Bambamboole\LaravelOidc\Server\Authentication\Events\LoggedOut;
use Illuminate\Auth\Events\Logout;

final readonly class DispatchLoggedOut
{
    public function handle(Logout $event): void
    {
        if ($event->guard !== config('oidc.auth.guard', 'identity') || $event->user === null) {
            return;
        }

        event(new LoggedOut((string) $event->user->getAuthIdentifier()));
    }
}
