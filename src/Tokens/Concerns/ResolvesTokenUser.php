<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;

trait ResolvesTokenUser
{
    private function resolveUser(?string $userIdentifier): ?Authenticatable
    {
        if ($userIdentifier === null) {
            return null;
        }

        $guard = config('oidc.auth.guard', 'identity');
        $provider = Auth::createUserProvider(config("auth.guards.{$guard}.provider"));

        return $provider?->retrieveById($userIdentifier);
    }
}
