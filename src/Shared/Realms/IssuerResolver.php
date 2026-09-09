<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Realms;

interface IssuerResolver
{
    public function url(): string;
}
