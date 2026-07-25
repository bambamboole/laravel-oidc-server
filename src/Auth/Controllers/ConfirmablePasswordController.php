<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\Views\PasswordConfirmationPrompt;
use Bambamboole\LaravelOidc\Auth\Views\PasswordConfirmationView;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

class ConfirmablePasswordController
{
    use ResolvesIdentityGuard;

    /**
     * PasswordConfirmationView is resolved here (not via the constructor) so
     * store() — which shares this class — never eagerly resolves a view the
     * request doesn't render.
     */
    public function show(Request $request): Responsable|Response
    {
        return app(PasswordConfirmationView::class)->respond(new PasswordConfirmationPrompt, $request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        $request->validate(['password' => ['required', 'string']]);

        $user = $this->currentUser($request);

        if ($user === null || ! Hash::check($request->string('password')->value(), (string) $user->getAuthPassword())) {
            throw ValidationException::withMessages(['password' => __('auth.password')]);
        }

        $request->session()->put('auth.password_confirmed_at', time());

        if ($request->wantsJson()) {
            return new JsonResponse('', 201);
        }

        return redirect()->intended($this->homeUrl());
    }
}
