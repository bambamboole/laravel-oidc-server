<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Scopes;

interface ScopeCatalog
{
    /** @return array<string, string> scope id => description */
    public function scopes(): array;
}
