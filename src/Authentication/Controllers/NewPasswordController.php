<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Controllers;

use Bambamboole\LaravelOidc\Server\Authentication\Actions\ResetPassword;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\InteractiveLoginFinalizer;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginOutcome;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordResetPrompt;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordResetView;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\ResolvesIdentityGuard;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

class NewPasswordController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly ResetPassword $reset,
        private readonly InteractiveLoginFinalizer $finalizer,
    ) {}

    /**
     * PasswordResetView is resolved here (not via the constructor) so
     * store() — which shares this class — never eagerly resolves a view the
     * request doesn't render.
     */
    public function create(Request $request): Responsable|Response
    {
        $email = $request->input('email');
        $status = $request->session()->get('status');

        return app(PasswordResetView::class)->respond(new PasswordResetPrompt(
            token: (string) $request->route('token'),
            email: is_string($email) ? $email : null,
            status: is_string($status) ? $status : null,
        ), $request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        // `confirmed` is the one password rule the package owns: the shipped
        // reset page renders a confirmation field, and without the rule a typo
        // would silently commit the first value. Every other rule (length,
        // strength, history) stays with the reset action.
        $request->validate([
            'token' => ['required'],
            'email' => ['required', 'email'],
            'password' => ['required', 'confirmed'],
        ]);

        $result = ($this->reset)($request->all());

        if ($result->user !== null) {
            // The password is reset either way; a postLogin denial or pending
            // second factor only affects the session that follows.
            $outcome = $this->finalizer->finalize($request, $result->user, 'pwd');

            if ($outcome === LoginOutcome::MfaChallenge) {
                return $request->wantsJson()
                    ? new JsonResponse(['two_factor' => true])
                    : redirect()->route('identity.two-factor.login');
            }

            return $request->wantsJson()
                ? new JsonResponse(['status' => __($result->status)], 200)
                : redirect()->route('identity.login')->with('status', __($result->status));
        }

        if ($request->wantsJson()) {
            throw ValidationException::withMessages(['email' => [__($result->status)]]);
        }

        return back()->withInput($request->only('email'))->withErrors(['email' => __($result->status)]);
    }
}
