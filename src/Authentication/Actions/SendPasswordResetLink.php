<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Actions;

use Illuminate\Support\Facades\Password;

final class SendPasswordResetLink
{
    public function __invoke(string $email): string
    {
        return Password::broker((string) config('auth.defaults.passwords', 'users'))
            ->sendResetLink(['email' => strtolower($email)]);
    }
}
