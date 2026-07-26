<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Session;

use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Contracts\SessionTokenProvider;
use Illuminate\Auth\Events\Login;
use Throwable;

class EstablishSessionToken
{
    public function __construct(
        private readonly SessionTokenProvider $tokens,
        private readonly FirstPartyClientConfig $firstPartyClient,
    ) {}

    public function handle(Login $event): void
    {
        if ($event->guard !== SessionTokenGuard::name()) {
            return;
        }

        if (! $this->firstPartyClient->isConfigured()) {
            return;
        }

        try {
            $this->tokens->establish($event->user);
        } catch (Throwable $e) {
            report($e);
        }
    }
}
