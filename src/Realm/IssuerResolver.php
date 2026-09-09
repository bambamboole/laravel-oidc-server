<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realm;

interface IssuerResolver
{
    public function url(): string;
}
