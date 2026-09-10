<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering\Actions;

use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Bambamboole\LaravelOidc\Server\Brokering\SocialAccountAlreadyLinkedException;
use Bambamboole\LaravelOidc\Server\Brokering\SocialAccountManager;
use Bambamboole\LaravelOidc\Server\Shared\Brokering\SocialUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * An identity already linked to a different local user is refused rather
 * than moved.
 */
final readonly class LinkSocialAccount
{
    public function __construct(private SocialAccountManager $accounts) {}

    /**
     * @param  Authenticatable&Model  $user
     *
     * @throws SocialAccountAlreadyLinkedException
     */
    public function __invoke(Authenticatable $user, string $providerKey, SocialUser $socialUser): void
    {
        $existing = $this->accounts->findAccount($providerKey, $socialUser->id);

        if ($existing instanceof SocialAccount && ! $existing->authenticatable->is($user)) {
            throw new SocialAccountAlreadyLinkedException;
        }

        $this->accounts->link($user, $providerKey, $socialUser);
    }
}
