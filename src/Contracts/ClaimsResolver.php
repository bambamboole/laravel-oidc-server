<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Contracts;

use Bambamboole\LaravelOidc\Claims\ClaimSet;
use Illuminate\Contracts\Auth\Authenticatable;

interface ClaimsResolver
{
    public function resolve(Authenticatable $user): ClaimSet;
}
