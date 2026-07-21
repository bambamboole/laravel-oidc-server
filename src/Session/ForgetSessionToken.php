<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Session;

use Bambamboole\LaravelOidc\Contracts\SessionTokenProvider;
use Illuminate\Auth\Events\Logout;

class ForgetSessionToken
{
    public function __construct(private readonly SessionTokenProvider $tokens) {}

    public function handle(Logout $event): void
    {
        $this->tokens->forget();
    }
}
