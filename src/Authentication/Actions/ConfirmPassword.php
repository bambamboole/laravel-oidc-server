<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Bambamboole\LaravelOidc\Server\Authentication\PasswordConfirmation;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Hash;
use SensitiveParameter;

/**
 * Re-checks the user's password and stamps the confirmation on the
 * session so password-confirmed routes open for the configured window.
 */
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
