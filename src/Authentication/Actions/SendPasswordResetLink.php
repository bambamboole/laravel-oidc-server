<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Illuminate\Contracts\Auth\PasswordBroker;

/**
 * Sends the reset link of the realm it runs in; wrap the call in
 * CurrentRealm::runAs() to send one for another realm's user.
 */
readonly class SendPasswordResetLink
{
    public function __construct(private PasswordBroker $broker) {}

    public function __invoke(string $email): string
    {
        return $this->broker->sendResetLink(['email' => strtolower($email)]);
    }
}
