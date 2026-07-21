<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Scopes;

final readonly class Scope
{
    public function __construct(
        public string $id,
        public string $description = '',
        public bool $hidden = false,
    ) {}
}
