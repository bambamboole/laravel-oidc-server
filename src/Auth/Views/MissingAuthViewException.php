<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Views;

use RuntimeException;

/**
 * Thrown by the default container binding for an auth view contract when no
 * ui package or app binding has replaced it.
 */
class MissingAuthViewException extends RuntimeException
{
    public static function forContract(string $contract): self
    {
        return new self("No view is bound for [{$contract}]. Install bambamboole/laravel-oidc-ui or bind the contract yourself.");
    }
}
