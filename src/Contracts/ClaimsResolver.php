<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Contracts;

use Bambamboole\LaravelOidc\Server\Claims\ClaimSet;
use Illuminate\Contracts\Auth\Authenticatable;

interface ClaimsResolver
{
    public function resolve(Authenticatable $user): ClaimSet;
}
