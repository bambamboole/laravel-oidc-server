<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor\Concerns;

use Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts\FactorAuthenticatable;
use Illuminate\Contracts\Auth\Authenticatable;
use LogicException;

trait InteractsWithFactorUser
{
    private function factorUser(Authenticatable $user): FactorAuthenticatable
    {
        if (! $user instanceof FactorAuthenticatable) {
            throw new LogicException('The authenticatable model must implement the FactorAuthenticatable contract.');
        }

        return $user;
    }
}
