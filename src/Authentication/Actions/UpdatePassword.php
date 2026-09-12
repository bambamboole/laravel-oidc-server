<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Bambamboole\LaravelOidc\Server\Authentication\Events\PasswordChanged;
use Bambamboole\LaravelOidc\Server\Shared\Credentials\PasswordCredential;
use Bambamboole\LaravelOidc\Server\Shared\Users\ResetUserPassword;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Str;

/**
 * A password change by a user who is already identified — from the account
 * screen, or because the realm's rotation window ran out. Persistence goes
 * through the same ResetUserPassword binding the reset flow uses: the
 * application owns the column either way, and rotating the remember token
 * cuts loose the other browsers holding the old one.
 */
readonly class UpdatePassword
{
    public function __construct(
        protected Container $container,
        protected PasswordCredential $passwords,
    ) {}

    public function enabled(): bool
    {
        return $this->container->bound(ResetUserPassword::class);
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function __invoke(Authenticatable&CanResetPassword $user, array $input): void
    {
        $this->passwords->validate($user, is_string($input['password'] ?? null) ? $input['password'] : '');

        $this->container->make(ResetUserPassword::class)($user, $input);

        if (method_exists($user, 'setRememberToken')) {
            $user->setRememberToken(Str::random(60));
        }

        if (method_exists($user, 'save')) {
            $user->save();
        }

        $this->passwords->record($user);

        event(new PasswordChanged((string) $user->getAuthIdentifier()));
    }
}
