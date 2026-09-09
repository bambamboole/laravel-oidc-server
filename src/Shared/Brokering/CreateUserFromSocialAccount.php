<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Brokering;

use Bambamboole\LaravelOidc\Server\Shared\Brokering\SocialUser;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Bind an implementation to enable just-in-time provisioning from an upstream
 * identity; brokered logins for unknown users fail while nothing is bound.
 */
interface CreateUserFromSocialAccount
{
    public function __invoke(SocialUser $socialUser, string $provider): Authenticatable;
}
