<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

use Laravel\Passport\Scope as PassportScope;

final class Scope extends PassportScope
{
    public function __construct(
        string $id,
        string $description = '',
        public bool $hidden = false,
    ) {
        parent::__construct($id, $description);
    }
}
