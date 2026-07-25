<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Views;

final readonly class EmailVerificationPrompt
{
    public function __construct(
        public ?string $status = null,
    ) {}
}
