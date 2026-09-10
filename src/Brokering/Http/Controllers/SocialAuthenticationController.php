<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Brokering\Actions\LinkSocialAccount;
use Bambamboole\LaravelOidc\Server\Brokering\Contracts\SocialProvider;
use Bambamboole\LaravelOidc\Server\Brokering\Events\SocialLoginFailed;
use Bambamboole\LaravelOidc\Server\Brokering\Exceptions\InvalidStateException;
use Bambamboole\LaravelOidc\Server\Brokering\Exceptions\SocialAccountAlreadyLinkedException;
use Bambamboole\LaravelOidc\Server\Brokering\Exceptions\SocialAuthenticationException;
use Bambamboole\LaravelOidc\Server\Brokering\PendingSocialRedirect;
use Bambamboole\LaravelOidc\Server\Brokering\SocialAccountManager;
use Bambamboole\LaravelOidc\Server\Brokering\SocialProviderRegistry;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\LoginFinalizer;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\LoginOutcome;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Shared\Brokering\SocialUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

class SocialAuthenticationController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly SocialProviderRegistry $providers,
        private readonly SocialAccountManager $accounts,
        private readonly LinkSocialAccount $linkAccount,
        private readonly LoginFinalizer $finalizer,
    ) {}

    public function redirect(Request $request, string $provider): Response
    {
        return $this->provider($provider)->redirect($request);
    }

    public function callback(Request $request, string $provider): RedirectResponse
    {
        if ($request->isMethod('POST')) {
            // A cross-site form_post (Apple) is sent without the session
            // cookie under SameSite=Lax; bounce to a top-level GET, where the
            // cookie is sent and the state can be validated.
            return redirect()->to(
                $request->url().'?'.http_build_query($request->only(['code', 'state', 'error', 'user'])),
                303,
            );
        }

        $driver = $this->provider($provider);

        if ($request->filled('error')) {
            return $this->failed(__('The sign-in was cancelled or refused by the provider.'));
        }

        $pending = PendingSocialRedirect::pull($request);

        if (! $pending instanceof PendingSocialRedirect) {
            return $this->failed(__('Your sign-in attempt expired. Please try again.'));
        }

        // Also covers completeLogin/completeLink: linking and JIT provisioning
        // (the app's CreateUserFromSocialAccount action) may reject the identity
        // with a SocialAuthenticationException, which must read as a failed
        // login, not a 500.
        try {
            $socialUser = $driver->user($request, $pending);

            return $pending->intent === PendingSocialRedirect::INTENT_LINK
                ? $this->completeLink($request, $provider, $socialUser)
                : $this->completeLogin($request, $provider, $socialUser);
        } catch (InvalidStateException) {
            return $this->failed(__('Your sign-in attempt expired. Please try again.'));
        } catch (SocialAuthenticationException $exception) {
            Log::warning("oidc: social authentication with [{$provider}] failed: {$exception->getMessage()}");
            event(new SocialLoginFailed($provider, $exception->getMessage()));

            return $this->failed(__('We could not sign you in with this account.'));
        }
    }

    private function completeLogin(Request $request, string $providerKey, SocialUser $socialUser): RedirectResponse
    {
        $guard = $this->sessionGuard();

        if ($guard->check()) {
            return redirect()->intended($this->homeUrl());
        }

        $user = $this->accounts->resolveUser($providerKey, $socialUser, $guard->getProvider());

        if (! $user instanceof Authenticatable) {
            return $this->failed(__('We could not sign you in with this account.'));
        }

        return match ($this->finalizer->finalize($request, $user, $providerKey)) {
            LoginOutcome::Denied => $this->failed(__('We could not sign you in with this account.')),
            LoginOutcome::MfaChallenge => redirect()->route('identity.two-factor.login'),
            LoginOutcome::LoggedIn => redirect()->intended($this->homeUrl()),
        };
    }

    private function completeLink(Request $request, string $providerKey, SocialUser $socialUser): RedirectResponse
    {
        $user = $this->currentUser($request);

        if (! $user instanceof Authenticatable) {
            return $this->failed(__('Please log in before linking an account.'));
        }

        if (! $user instanceof Model) {
            throw new RuntimeException('Social accounts require an Eloquent user model.');
        }

        try {
            ($this->linkAccount)($user, $providerKey, $socialUser);
        } catch (SocialAccountAlreadyLinkedException) {
            return redirect($this->homeUrl())->withErrors(['social' => __('This account is already linked to another user.')]);
        }

        return redirect($this->homeUrl())->with('status', 'social-account-linked');
    }

    private function provider(string $key): SocialProvider
    {
        return $this->providers->get($key) ?? abort(404);
    }

    private function failed(string $message): RedirectResponse
    {
        return redirect()->route('identity.login')->withErrors(['social' => $message]);
    }
}
