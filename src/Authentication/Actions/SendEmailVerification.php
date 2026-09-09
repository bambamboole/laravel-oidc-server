<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Illuminate\Contracts\Auth\MustVerifyEmail;

/**
 * Returns false when the address is already verified and nothing was sent.
 */
final class SendEmailVerification
{
    public function __invoke(MustVerifyEmail $user): bool
    {
        if ($user->hasVerifiedEmail()) {
            return false;
        }

        $user->sendEmailVerificationNotification();

        return true;
    }
}
