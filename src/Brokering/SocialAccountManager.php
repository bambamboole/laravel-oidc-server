<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering;

use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Bambamboole\LaravelOidc\Server\Shared\Brokering\CreateUserFromSocialAccount;
use Bambamboole\LaravelOidc\Server\Shared\Brokering\SocialUser;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RuntimeException;

class SocialAccountManager
{
    public function __construct(
        private readonly Container $container,
        private readonly RealmResolver $realms,
    ) {}

    public function findAccount(string $provider, string $providerUserId): ?SocialAccount
    {
        return SocialAccount::query()
            ->inRealm()
            ->where('provider', $provider)
            ->where('provider_user_id', $providerUserId)
            ->first();
    }

    public function resolveUser(string $provider, SocialUser $socialUser, UserProvider $users): ?Authenticatable
    {
        $account = $this->findAccount($provider, $socialUser->id);

        if ($account instanceof SocialAccount) {
            $this->sync($account, $socialUser);

            return $users->retrieveById($account->user_id);
        }

        $brokering = $this->realms->current()->brokering();

        if ($brokering->linkByVerifiedEmail && $socialUser->emailVerified && $socialUser->email !== null) {
            $user = $users->retrieveByCredentials(['email' => $socialUser->email]);

            if ($user !== null) {
                $this->link($user, $provider, $socialUser);

                return $user;
            }
        }

        if ($brokering->autoProvision && $this->container->bound(CreateUserFromSocialAccount::class)) {
            $user = $this->container->make(CreateUserFromSocialAccount::class)($socialUser, $provider);
            $this->link($user, $provider, $socialUser);

            return $user;
        }

        return null;
    }

    public function link(Authenticatable $user, string $provider, SocialUser $socialUser): SocialAccount
    {
        if (! $user instanceof Model) {
            throw new RuntimeException('Social accounts require an Eloquent user model.');
        }

        $account = $this->findAccount($provider, $socialUser->id) ?? (new SocialAccount)->forceFill([
            'realm_id' => $this->realms->current()->identifier(),
            'provider' => $provider,
            'provider_user_id' => $socialUser->id,
        ]);

        $account->user_id = (string) $user->getAuthIdentifier();

        $this->sync($account, $socialUser);

        return $account;
    }

    private function sync(SocialAccount $account, SocialUser $socialUser): void
    {
        $account->fill([
            'email' => $socialUser->email ?? $account->email,
            // Apple only delivers the name on first consent; never null it out.
            'name' => $socialUser->name ?? $account->name,
            'nickname' => $socialUser->nickname ?? $account->nickname,
            'avatar' => $socialUser->avatar ?? $account->avatar,
            'access_token' => $socialUser->accessToken,
            'refresh_token' => $socialUser->refreshToken ?? $account->refresh_token,
            'token_expires_at' => $socialUser->expiresIn !== null ? now()->addSeconds($socialUser->expiresIn) : null,
            'raw' => $socialUser->raw,
        ]);

        $account->save();
    }
}
