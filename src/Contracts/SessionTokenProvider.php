<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface SessionTokenProvider
{
    public function currentToken(): ?string;

    public function establish(Authenticatable $user): void;

    public function forget(): void;
}
