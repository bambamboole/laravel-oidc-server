<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Views;

final readonly class LoginPrompt
{
    public function __construct(
        public ?string $status = null,
    ) {}
}
