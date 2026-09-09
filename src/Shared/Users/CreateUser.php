<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Users;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Bind an implementation to enable self-registration; the register endpoint
 * answers 404 while nothing is bound.
 */
interface CreateUser
{
    /**
     * @param  array<string, mixed>  $input
     */
    public function __invoke(array $input): Authenticatable;
}
