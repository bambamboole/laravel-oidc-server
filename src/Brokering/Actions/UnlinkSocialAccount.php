<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering\Actions;

use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Authenticatable;

class UnlinkSocialAccount
{
    /**
     * @throws AuthorizationException when the account belongs to someone else
     */
    public function __invoke(Authenticatable $user, SocialAccount $account): void
    {
        if ($account->user_id !== (string) $user->getAuthIdentifier()) {
            throw new AuthorizationException;
        }

        $account->delete();
    }
}
