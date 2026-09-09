<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Forms;

final readonly class EmailVerificationPrompt
{
    public function __construct(
        public ?string $status = null,
    ) {}
}
