<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Session;

use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Illuminate\Auth\Events\Login;

class StartOidcSession
{
    public function __construct(private readonly SessionRegistry $registry) {}

    public function handle(Login $event): void
    {
        if ($event->guard !== config('passport.guard')) {
            return;
        }

        $sid = $this->registry->start((string) $event->user->getAuthIdentifier());

        if (app()->bound('session.store')) {
            app('session.store')->put([
                'oidc.auth_time' => time(),
                'oidc.sid' => $sid,
            ]);
        }
    }
}
