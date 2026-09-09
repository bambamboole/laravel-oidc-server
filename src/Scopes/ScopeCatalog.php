<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

interface ScopeCatalog
{
    /** @return array<string, string> scope id => description */
    public function scopes(): array;
}
