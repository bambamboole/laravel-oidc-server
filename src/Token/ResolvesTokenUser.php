<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Token;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;

trait ResolvesTokenUser
{
    private function resolveUser(?string $userIdentifier): ?Authenticatable
    {
        if ($userIdentifier === null) {
            return null;
        }

        $guard = config('passport.guard') ?? config('auth.defaults.guard');
        $provider = Auth::createUserProvider(config("auth.guards.{$guard}.provider"));

        return $provider?->retrieveById($userIdentifier);
    }
}
