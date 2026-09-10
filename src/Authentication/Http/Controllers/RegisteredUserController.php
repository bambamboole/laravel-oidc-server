<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Authentication\Actions\RegisterUser;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\InteractiveLoginFinalizer;
use Bambamboole\LaravelOidc\Server\Authentication\Views\RegisterView;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\LoginOutcome;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\ResolvesIdentityGuard;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RegisteredUserController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly RegisterUser $register,
        private readonly InteractiveLoginFinalizer $finalizer,
    ) {}

    /**
     * RegisterView is resolved here (not via the constructor) so store() —
     * which shares this class — never eagerly resolves a view the request
     * doesn't render.
     */
    public function create(Request $request): Responsable|Response
    {
        return app(RegisterView::class)->respond($request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        // Registration without a bound CreateUser action is disabled, not
        // broken — so 404, not 500.
        abort_unless($this->register->enabled(), 404);

        $user = ($this->register)($request->all());

        // The account exists either way; a postLogin denial only refuses the
        // session, so the user lands on the login page instead.
        return match ($this->finalizer->finalize($request, $user, 'pwd')) {
            LoginOutcome::Denied => $request->wantsJson()
                ? new JsonResponse('', 403)
                : redirect()->route('identity.login'),
            LoginOutcome::MfaChallenge => $request->wantsJson()
                ? new JsonResponse(['two_factor' => true])
                : redirect()->route('identity.two-factor.login'),
            LoginOutcome::LoggedIn => $request->wantsJson()
                ? new JsonResponse('', 201)
                : redirect()->intended($this->homeUrl()),
        };
    }
}
