<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Contracts;

interface ScopeCatalog
{
    /** @return array<string, string> scope id => description */
    public function scopes(): array;
}
