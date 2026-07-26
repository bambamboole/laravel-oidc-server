<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\Pipeline\InteractiveLoginFinalizer;
use Bambamboole\LaravelOidc\Auth\Pipeline\LoginOutcome;
use Bambamboole\LaravelOidc\Auth\Views\LoginPrompt;
use Bambamboole\LaravelOidc\Auth\Views\LoginView;
use Bambamboole\LaravelOidc\Routing\Handler;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

class AuthenticatedSessionController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly InteractiveLoginFinalizer $finalizer,
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

        $provider = $this->sessionGuard()->getProvider();
        $user = $provider->retrieveByCredentials($credentials);

        if ($user === null || ! $provider->validateCredentials($user, $credentials)) {
            throw ValidationException::withMessages([$username => __('auth.failed')]);
        }

        if (config('hashing.rehash_on_login', true)) {
            $provider->rehashPasswordIfRequired($user, $credentials);
        }

        return match ($this->finalizer->finalize($request, $user, 'pwd', $request->boolean('remember'))) {
            LoginOutcome::Denied => throw ValidationException::withMessages([$username => __('auth.failed')]),
            LoginOutcome::MfaChallenge => $request->wantsJson()
                ? new JsonResponse(['two_factor' => true])
                : redirect()->route(Handler::TwoFactorLogin->value),
            LoginOutcome::LoggedIn => $request->wantsJson()
                ? new JsonResponse('', 200)
                : redirect()->intended($this->homeUrl()),
        };
    }
}
