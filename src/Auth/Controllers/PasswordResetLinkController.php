<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Views\PasswordResetRequestPrompt;
use Bambamboole\LaravelOidc\Auth\Views\PasswordResetRequestView;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

class PasswordResetLinkController
{
    /**
     * PasswordResetRequestView is resolved here (not via the constructor) so
     * store() — which shares this class — never eagerly resolves a view the
     * request doesn't render.
     */
    public function create(Request $request): Responsable|Response
    {
        $status = $request->session()->get('status');

        return app(PasswordResetRequestView::class)->respond(new PasswordResetRequestPrompt(
            status: is_string($status) ? $status : null,
        ), $request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        $request->validate(['email' => ['required', 'email']]);

        $status = Password::broker((string) config('auth.defaults.passwords', 'users'))
            ->sendResetLink(['email' => $request->string('email')->lower()->value()]);

        if ($status === Password::RESET_LINK_SENT) {
            return $request->wantsJson()
                ? new JsonResponse(['status' => __($status)], 200)
                : back()->with('status', __($status));
        }

        if ($request->wantsJson()) {
            throw ValidationException::withMessages(['email' => [__($status)]]);
        }

        return back()->withInput($request->only('email'))->withErrors(['email' => __($status)]);
    }
}
