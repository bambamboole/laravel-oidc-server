<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts;

use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorEnrollment;
use Illuminate\Contracts\Auth\Authenticatable;

interface EnrollableFactorProvider extends FactorProvider
{
    public function beginEnrollment(Authenticatable $user, ?string $name = null): FactorEnrollment;

    public function revoke(Authenticatable $user, FactorEnrollment $enrollment): void;
}
