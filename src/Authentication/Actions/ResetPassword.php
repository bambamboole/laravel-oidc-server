<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Bambamboole\LaravelOidc\Server\Authentication\Events\PasswordReset;
use Bambamboole\LaravelOidc\Server\Authentication\PasswordResetResult;
use Bambamboole\LaravelOidc\Server\Shared\Credentials\PasswordCredential;
use Bambamboole\LaravelOidc\Server\Shared\Users\ResetUserPassword;
use Illuminate\Auth\Events\PasswordReset as PasswordWasReset;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Validates the reset token against the realm's PasswordResetTokens, checks
 * the new password against the realm's policy, and hands the user to the
 * app's ResetUserPassword binding, which owns persistence. Signing the user
 * in afterwards is the caller's job.
 */
readonly class ResetPassword
{
    public function __construct(
        protected Container $container,
        protected PasswordCredential $passwords,
        protected PasswordBroker $broker,
    ) {}

    /**
     * @param  array<string, mixed>  $input  the full reset request (token, email, password, password_confirmation, …)
     */
    public function __invoke(array $input): PasswordResetResult
    {
        $resetUser = null;

        $status = $this->broker->reset(
            array_intersect_key($input, array_flip(['email', 'password', 'password_confirmation', 'token'])),
            function (CanResetPassword $user) use ($input, &$resetUser): void {
                if (! $user instanceof Authenticatable) {
                    throw new RuntimeException('The reset password user must be authenticatable.');
                }

                $this->passwords->validate($user, is_string($input['password'] ?? null) ? $input['password'] : '');

                $this->container->make(ResetUserPassword::class)($user, $input);

                if (method_exists($user, 'setRememberToken')) {
                    $user->setRememberToken(Str::random(60));
                }

                if (method_exists($user, 'save')) {
                    $user->save();
                }

                $this->passwords->record($user);

                event(new PasswordWasReset($user));

                $resetUser = $user;
            },
        );

        if ($status === Password::PASSWORD_RESET && $resetUser instanceof Authenticatable) {
            event(new PasswordReset((string) $resetUser->getAuthIdentifier()));

            return new PasswordResetResult($status, $resetUser);
        }

        return new PasswordResetResult(is_string($status) ? $status : Password::INVALID_TOKEN, null);
    }
}
