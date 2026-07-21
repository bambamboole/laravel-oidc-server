<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\AuthenticationMethods;
use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesPendingAuthorization;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorRegistry;
use Bambamboole\LaravelOidc\Auth\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Auth\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Auth\Social\Contracts\SocialProvider;
use Bambamboole\LaravelOidc\Auth\Social\InvalidStateException;
use Bambamboole\LaravelOidc\Auth\Social\PendingAuthorization;
use Bambamboole\LaravelOidc\Auth\Social\SocialAccountManager;
use Bambamboole\LaravelOidc\Auth\Social\SocialAuthenticationException;
use Bambamboole\LaravelOidc\Auth\Social\SocialProviderRegistry;
use Bambamboole\LaravelOidc\Auth\Social\SocialUser;
use Bambamboole\LaravelOidc\Contracts\DeviceRecognizer;
use Bambamboole\LaravelOidc\Routing\Handler;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use RuntimeException;

class SocialAuthenticationController
{
    use ResolvesIdentityGuard;
    use ResolvesPendingAuthorization;

    public function __construct(
        private readonly SocialProviderRegistry $providers,
        private readonly SocialAccountManager $accounts,
        private readonly FactorRegistry $factors,
        private readonly AuthenticationMethods $context,
        private readonly PostLoginPipeline $pipeline,
        private readonly DeviceRecognizer $deviceRecognizer,
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

        $this->context->start($providerKey);

        $api = $this->pipeline->run(new LoginEvent(
            user: $user,
            client: $this->pendingClient($request),
            scopes: $this->pendingScopes($request),
            requestedAcrValues: [],
            ip: $request->ip(),
            userAgent: $request->userAgent(),
            amr: [$providerKey],
            authTime: null,
            recognizer: $this->deviceRecognizer,
            request: $request,
        ));

        if ($api->isDenied()) {
            Log::warning('oidc: social login denied by postLogin', ['reason' => $api->denyReason()]);
            $this->context->forget();

            return $this->failed($request, __('We could not sign you in with this account.'));
        }

        $request->session()->put('oidc.id_token_claims', $api->idTokenClaims());
        $request->session()->put('oidc.access_token_claims', $api->accessTokenClaims());

        $challengeProviders = array_values(array_filter(
            (array) config('oidc.auth.two_factor.challenge_providers', ['totp']),
            is_string(...),
        ));
        $enrollments = $this->factors->challengeableEnrollments($user, $challengeProviders);

        if ($api->mfaRequired() && $enrollments === []) {
            Log::warning('oidc: social login denied, MFA required but no challengeable factor');
            $this->context->forget();

            return $this->failed($request, __('We could not sign you in with this account.'));
        }

        if ($enrollments !== []) {
            $request->session()->put([
                'login.id' => $user->getAuthIdentifier(),
                'login.remember' => false,
                'login.factor' => $enrollments[0]->providerKey,
                'login.factor_id' => $enrollments[0]->id,
            ]);

            return redirect()->route(Handler::TwoFactorLogin->value);
        }

        $guard->login($user);
        $request->session()->regenerate();

        return redirect()->intended($this->homeUrl());
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
