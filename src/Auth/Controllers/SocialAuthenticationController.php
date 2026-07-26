<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\Pipeline\InteractiveLoginFinalizer;
use Bambamboole\LaravelOidc\Auth\Pipeline\LoginOutcome;
use Bambamboole\LaravelOidc\Auth\Social\Contracts\SocialProvider;
use Bambamboole\LaravelOidc\Auth\Social\InvalidStateException;
use Bambamboole\LaravelOidc\Auth\Social\PendingAuthorization;
use Bambamboole\LaravelOidc\Auth\Social\SocialAccountManager;
use Bambamboole\LaravelOidc\Auth\Social\SocialAuthenticationException;
use Bambamboole\LaravelOidc\Auth\Social\SocialProviderRegistry;
use Bambamboole\LaravelOidc\Auth\Social\SocialUser;
use Bambamboole\LaravelOidc\Routing\Handler;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use RuntimeException;

class SocialAuthenticationController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly SocialProviderRegistry $providers,
        private readonly SocialAccountManager $accounts,
        private readonly InteractiveLoginFinalizer $finalizer,
    ) {}

    public function redirect(Request $request, string $provider): RedirectResponse
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
            return $this->failed($request, __('The sign-in was cancelled or refused by the provider.'));
        }

        $pending = PendingAuthorization::pull($request);

        if ($pending === null) {
            return $this->failed($request, __('Your sign-in attempt expired. Please try again.'));
        }

        try {
            $socialUser = $driver->user($request, $pending);
        } catch (InvalidStateException) {
            return $this->failed($request, __('Your sign-in attempt expired. Please try again.'));
        } catch (SocialAuthenticationException $exception) {
            Log::warning("oidc: social authentication with [{$provider}] failed: {$exception->getMessage()}");

            return $this->failed($request, __('We could not sign you in with this account.'));
        }

        return $pending->intent === PendingAuthorization::INTENT_LINK
            ? $this->completeLink($request, $provider, $socialUser)
            : $this->completeLogin($request, $provider, $socialUser);
    }

    private function completeLogin(Request $request, string $providerKey, SocialUser $socialUser): RedirectResponse
    {
        $guard = $this->sessionGuard();

        if ($guard->check()) {
            return redirect()->intended($this->homeUrl());
        }

        $user = $this->accounts->resolveUser($providerKey, $socialUser, $guard->getProvider());

        if ($user === null) {
            return $this->failed($request, __('We could not sign you in with this account.'));
        }

        return match ($this->finalizer->finalize($request, $user, $providerKey)) {
            LoginOutcome::Denied => $this->failed($request, __('We could not sign you in with this account.')),
            LoginOutcome::MfaChallenge => redirect()->route(Handler::TwoFactorLogin->value),
            LoginOutcome::LoggedIn => redirect()->intended($this->homeUrl()),
        };
    }

    private function completeLink(Request $request, string $providerKey, SocialUser $socialUser): RedirectResponse
    {
        $user = $this->currentUser($request);

        if ($user === null) {
            return $this->failed($request, __('Please log in before linking an account.'));
        }

        if (! $user instanceof Model) {
            throw new RuntimeException('Social accounts require an Eloquent user model.');
        }

        $existing = $this->accounts->findAccount($providerKey, $socialUser->id);

        if ($existing !== null && ! $existing->authenticatable->is($user)) {
            return redirect($this->homeUrl())->withErrors(['social' => __('This account is already linked to another user.')]);
        }

        $this->accounts->link($user, $providerKey, $socialUser);

        return redirect($this->homeUrl())->with('status', 'social-account-linked');
    }

    private function provider(string $key): SocialProvider
    {
        return $this->providers->get($key) ?? abort(404);
    }

    private function failed(Request $request, string $message): RedirectResponse
    {
        return redirect()->route(Handler::Login->value)->withErrors(['social' => $message]);
    }
}
