<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Bambamboole\LaravelOidc\Server\Authentication\PasswordConfirmation;
use Bambamboole\LaravelOidc\Server\Shared\Credentials\PasswordCredential;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use SensitiveParameter;

final readonly class ConfirmPassword
{
    public function __construct(private PasswordCredential $passwords) {}

    public function __invoke(Authenticatable $user, #[SensitiveParameter] string $password, Session $session): bool
    {
        if (! $this->passwords->verify($user, $password)) {
            return false;
        }

        PasswordConfirmation::confirm($session);

        return true;
    }
}
