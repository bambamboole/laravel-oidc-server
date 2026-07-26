<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Views;

final readonly class PasswordResetPrompt
{
    public function __construct(
        public string $token,
        public ?string $email = null,
        public ?string $status = null,
    ) {}
}
