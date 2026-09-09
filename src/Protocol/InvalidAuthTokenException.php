<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol;

use Illuminate\Auth\Access\AuthorizationException;

final class InvalidAuthTokenException extends AuthorizationException
{
    public static function different(): static
    {
        return new self('The provided auth token for the request is different from the session auth token.');
    }
}
