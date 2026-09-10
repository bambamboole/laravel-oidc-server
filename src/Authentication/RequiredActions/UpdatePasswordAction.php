<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\RequiredActions;

use Bambamboole\LaravelOidc\Server\Shared\Authentication\RequiredAction;
use Bambamboole\LaravelOidc\Server\Shared\Credentials\PasswordCredential;
use Bambamboole\LaravelOidc\Server\Shared\Realms\Realm;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;

/**
 * The consumer of the realm's `max_age_days`. The rotation clock starts at
 * the first password login the package sees, so a password it has never
 * tracked is not retroactively expired — enabling rotation does not lock out
 * everyone at once.
 */
final readonly class UpdatePasswordAction implements RequiredAction
{
    public function __construct(private PasswordCredential $passwords) {}

    public function key(): string
    {
        return 'update_password';
    }

    public function isPending(Authenticatable $user, Realm $realm): bool
    {
        return $user instanceof CanResetPassword && $this->passwords->isExpired($user);
    }

    public function route(): string
    {
        return 'identity.password.change';
    }
}
