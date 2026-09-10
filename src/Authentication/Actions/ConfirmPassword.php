<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Bambamboole\LaravelOidc\Server\Authentication\PasswordConfirmation;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Hash;
use SensitiveParameter;

final class ConfirmPassword
{
    public function __invoke(Authenticatable $user, #[SensitiveParameter] string $password, Session $session): bool
    {
        if (! Hash::check($password, (string) $user->getAuthPassword())) {
            return false;
        }

        PasswordConfirmation::confirm($session);

        return true;
    }
}
