<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\AuthViewManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;

class PasswordResetLinkController
{
    public function __construct(private readonly AuthViewManager $views) {}

    public function create(Request $request): mixed
    {
        return $this->views->render(AuthViewManager::RequestPasswordResetLink, $request);
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
