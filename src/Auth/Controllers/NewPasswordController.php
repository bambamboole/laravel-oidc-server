<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\UserActionManager;
use Bambamboole\LaravelOidc\Auth\Views\PasswordResetPrompt;
use Bambamboole\LaravelOidc\Auth\Views\PasswordResetView;
use Bambamboole\LaravelOidc\Routing\Handler;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

class NewPasswordController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly UserActionManager $actions,
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
        $request->validate([
            'token' => ['required'],
            'email' => ['required', 'email'],
            'password' => ['required'],
        ]);

        $status = Password::broker((string) config('auth.defaults.passwords', 'users'))->reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function (CanResetPassword $user) use ($request): void {
                $this->actions->resetUserPassword($user, $request->all());

                if (method_exists($user, 'setRememberToken')) {
                    $user->setRememberToken(Str::random(60));
                }

                if (method_exists($user, 'save')) {
                    $user->save();
                }

                if (! $user instanceof Authenticatable) {
                    throw new RuntimeException('The reset password user must be authenticatable.');
                }

                event(new PasswordReset($user));

                Auth::guard($this->guardName())->login($user);
            },
        );

        if ($status === Password::PASSWORD_RESET) {
            if ($request->hasSession()) {
                $request->session()->regenerate();
            }

            return $request->wantsJson()
                ? new JsonResponse(['status' => __($status)], 200)
                : redirect()->route(Handler::Login->value)->with('status', __($status));
        }

        if ($request->wantsJson()) {
            throw ValidationException::withMessages(['email' => [__($status)]]);
        }

        return back()->withInput($request->only('email'))->withErrors(['email' => __($status)]);
    }
}
