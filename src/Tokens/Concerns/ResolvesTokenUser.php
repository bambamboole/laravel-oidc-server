<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Concerns;

use Bambamboole\LaravelOidc\Server\Shared\Authentication\IdentityGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;

trait ResolvesTokenUser
{
    private function resolveUser(?string $userIdentifier): ?Authenticatable
    {
        if ($userIdentifier === null) {
            return null;
        }

        $guard = IdentityGuard::name();
        $provider = Auth::createUserProvider(config("auth.guards.{$guard}.provider"));

        return $provider?->retrieveById($userIdentifier);
    }
}
