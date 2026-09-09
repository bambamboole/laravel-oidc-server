<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Forms;

final readonly class PasswordResetRequestPrompt
{
    public function __construct(
        public ?string $status = null,
    ) {}
}
