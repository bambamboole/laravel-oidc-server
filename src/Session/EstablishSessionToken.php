<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Session;

use Bambamboole\LaravelOidc\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Contracts\SessionTokenProvider;
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
