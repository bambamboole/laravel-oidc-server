<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Social;

use Bambamboole\LaravelOidc\Auth\Social\Models\SocialAccount;
use Bambamboole\LaravelOidc\Auth\UserActionManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use RuntimeException;

class SocialAccountManager
{
    public function __construct(
        private readonly UserActionManager $userActions,
    ) {}

    public function findAccount(string $provider, string $providerUserId): ?SocialAccount
    {
        return SocialAccount::query()
            ->where('provider', $provider)
            ->where('provider_user_id', $providerUserId)
            ->first();
    }

    /**
     * Resolve the local user for an upstream identity: an existing link wins,
     * then (when enabled) a verified-email match, then (when enabled) JIT
     * provisioning. Null means the identity cannot be signed in.
     */
    public function resolveUser(string $provider, SocialUser $socialUser, UserProvider $users): ?Authenticatable
    {
        $account = $this->findAccount($provider, $socialUser->id);

        if ($account !== null) {
            $this->sync($account, $socialUser);

            $user = $account->authenticatable;

            return $user instanceof Authenticatable ? $user : null;
        }

        if (config('oidc.social.link_by_verified_email', true) && $socialUser->emailVerified && $socialUser->email !== null) {
            $user = $users->retrieveByCredentials(['email' => $socialUser->email]);

            if ($user !== null) {
                $this->link($user, $provider, $socialUser);

                return $user;
            }
        }

        if (config('oidc.social.auto_provision', true)) {
            $user = $this->userActions->createUserFromSocial($socialUser, $provider);

            if ($user !== null) {
                $this->link($user, $provider, $socialUser);

                return $user;
            }
        }

        return null;
    }

    public function link(Authenticatable $user, string $provider, SocialUser $socialUser): SocialAccount
    {
        if (! $user instanceof Model) {
            throw new RuntimeException('Social accounts require an Eloquent user model.');
        }

        $account = $this->findAccount($provider, $socialUser->id) ?? new SocialAccount([
            'provider' => $provider,
            'provider_user_id' => $socialUser->id,
        ]);

        $account->authenticatable()->associate($user);

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
