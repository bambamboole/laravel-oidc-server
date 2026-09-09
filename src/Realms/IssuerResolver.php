<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

interface IssuerResolver
{
    public function url(): string;
}
