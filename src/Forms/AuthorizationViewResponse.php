<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Forms;

use Illuminate\Contracts\Support\Responsable;

interface AuthorizationViewResponse extends Responsable
{
    /** @param  array<string, mixed>  $parameters */
    public function withParameters(array $parameters = []): static;
}
