<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Contracts;

interface IssuerResolver
{
    public function url(): string;
}
