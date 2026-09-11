<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The package's rows name their user without a foreign key, so there is no
 * relation for for() to go through.
 */
trait ForUser
{
    public function forUser(Authenticatable $user): static
    {
        return $this->state(['user_id' => (string) $user->getAuthIdentifier()]);
    }
}
