<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Views;

use Bambamboole\LaravelOidc\Server\Shared\Realms\Settings\LoginMethod;

final readonly class LoginPrompt
{
    /**
     * @param  list<LoginMethod>  $methods  the login methods this realm accepts; a method left out has its routes closed
     */
    public function __construct(
        public ?string $status = null,
        public array $methods = [LoginMethod::Password, LoginMethod::Passkey, LoginMethod::Social],
    ) {}

    public function allows(LoginMethod $method): bool
    {
        return in_array($method, $this->methods, true);
    }
}
