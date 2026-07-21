<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Claims;

use Bambamboole\LaravelOidc\Contracts\ClaimsResolver;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

class DefaultClaimsResolver implements ClaimsResolver
{
    public function resolve(Authenticatable $user): ClaimSet
    {
        if (! $user instanceof Model) {
            return new ClaimSet;
        }

        return new ClaimSet([
            'profile' => [
                'name' => $user->getAttribute('name'),
                'updated_at' => $user->getAttribute('updated_at')?->getTimestamp(),
            ],
            'email' => [
                'email' => $user->getAttribute('email'),
                'email_verified' => $user->getAttribute('email') !== null
                    ? $user->getAttribute('email_verified_at') !== null
                    : null,
            ],
        ]);
    }
}
