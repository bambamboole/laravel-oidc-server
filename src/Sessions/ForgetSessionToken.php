<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions;

use Bambamboole\LaravelOidc\Server\Shared\Sessions\SessionTokenProvider;
use Illuminate\Auth\Events\Logout;

class ForgetSessionToken
{
    public function __construct(private readonly SessionTokenProvider $tokens) {}

    public function handle(Logout $event): void
    {
        if ($event->guard !== SessionTokenGuard::name()) {
            return;
        }

        $this->tokens->forget();
    }
}
