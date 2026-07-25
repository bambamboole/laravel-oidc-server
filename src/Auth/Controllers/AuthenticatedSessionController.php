<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\AuthenticationMethods;
use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesPendingAuthorization;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorRegistry;
use Bambamboole\LaravelOidc\Auth\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Auth\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Auth\Views\LoginPrompt;
use Bambamboole\LaravelOidc\Auth\Views\LoginView;
use Bambamboole\LaravelOidc\Contracts\DeviceRecognizer;
use Bambamboole\LaravelOidc\Routing\Handler;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

class AuthenticatedSessionController
{
    use ResolvesIdentityGuard;
    use ResolvesPendingAuthorization;

    public function __construct(
        private readonly FactorRegistry $factors,
        private readonly AuthenticationMethods $context,
        private readonly PostLoginPipeline $pipeline,
        private readonly DeviceRecognizer $deviceRecognizer,
    ) {}

    /**
     * LoginView is resolved here (not via the constructor) so store() —
     * which shares this class — never eagerly resolves a view the request
     * doesn't render.
     */
    public function create(Request $request): Responsable|Response
    {
        $status = $request->session()->get('status');

        return app(LoginView::class)->respond(new LoginPrompt(
            status: is_string($status) ? $status : null,
        ), $request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        $username = (string) config('oidc.auth.username', 'email');

        $request->validate([
            $username => ['required', 'string'],
            'password' => ['required', 'string'],
        ]);

        $credentials = [
            $username => $request->string($username)->lower()->value(),
            'password' => $request->string('password')->value(),
        ];

        $guard = $this->sessionGuard();

        $provider = $guard->getProvider();
        $user = $provider->retrieveByCredentials($credentials);

        if ($user === null || ! $provider->validateCredentials($user, $credentials)) {
            throw ValidationException::withMessages([$username => __('auth.failed')]);
        }

        if (config('hashing.rehash_on_login', true)) {
            $provider->rehashPasswordIfRequired($user, $credentials);
        }

        $this->context->start('pwd');

        $api = $this->pipeline->run(new LoginEvent(
            user: $user,
            client: $this->pendingClient($request),
            scopes: $this->pendingScopes($request),
            requestedAcrValues: [],
            ip: $request->ip(),
            userAgent: $request->userAgent(),
            amr: ['pwd'],
            authTime: null,
            recognizer: $this->deviceRecognizer,
            request: $request,
        ));

        if ($api->isDenied()) {
            Log::warning('oidc: login denied by postLogin', ['reason' => $api->denyReason()]);
            $this->context->forget();

            throw ValidationException::withMessages([$username => __('auth.failed')]);
        }

        $request->session()->put('oidc.id_token_claims', $api->idTokenClaims());
        $request->session()->put('oidc.access_token_claims', $api->accessTokenClaims());

        $challengeProviders = array_values(array_filter(
            (array) config('oidc.auth.two_factor.challenge_providers', ['totp']),
            is_string(...),
        ));
        $enrollments = $this->factors->challengeableEnrollments($user, $challengeProviders);

        if ($api->mfaRequired() && $enrollments === []) {
            Log::warning('oidc: login denied, MFA required but no challengeable factor');
            $this->context->forget();

            throw ValidationException::withMessages([$username => __('auth.failed')]);
        }

        if ($enrollments !== []) {
            $request->session()->put([
                'login.id' => $user->getAuthIdentifier(),
                'login.remember' => $request->boolean('remember'),
                'login.factor' => $enrollments[0]->providerKey,
                'login.factor_id' => $enrollments[0]->id,
            ]);

            if ($request->wantsJson()) {
                return new JsonResponse(['two_factor' => true]);
            }

            return redirect()->route(Handler::TwoFactorLogin->value);
        }

        $guard->login($user, $request->boolean('remember'));

        if ($request->hasSession()) {
            $request->session()->regenerate();
        }

        if ($request->wantsJson()) {
            return new JsonResponse('', 200);
        }

        return redirect()->intended($this->homeUrl());
    }
}
