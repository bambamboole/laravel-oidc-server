<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Authentication\Actions\AuthenticateWithPassword;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\InteractiveLoginFinalizer;
use Bambamboole\LaravelOidc\Server\Authentication\Views\LoginPrompt;
use Bambamboole\LaravelOidc\Server\Authentication\Views\LoginView;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\LoginOutcome;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Contracts\Auth\Authenticatable;
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
        private readonly AuthenticateWithPassword $authenticate,
        private readonly InteractiveLoginFinalizer $finalizer,
        private readonly RealmResolver $realms,
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
        $username = $this->realms->current()->login()->usernameField;

        $request->validate([
            $username => ['required', 'string'],
            'password' => ['required', 'string'],
        ]);

        $user = ($this->authenticate)(
            $this->sessionGuard()->getProvider(),
            $username,
            $request->string($username)->value(),
            $request->string('password')->value(),
        );

        if (! $user instanceof Authenticatable) {
            throw ValidationException::withMessages([$username => __('auth.failed')]);
        }

        return match ($this->finalizer->finalize($request, $user, 'pwd', $request->boolean('remember'))) {
            LoginOutcome::Denied => throw ValidationException::withMessages([$username => __('auth.failed')]),
            LoginOutcome::MfaChallenge => $request->wantsJson()
                ? new JsonResponse(['two_factor' => true])
                : redirect()->route('identity.two-factor.login'),
            LoginOutcome::LoggedIn => $request->wantsJson()
                ? new JsonResponse('', 200)
                : redirect()->intended($this->homeUrl()),
        };
    }
}
