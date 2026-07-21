<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\AuthViewManager;
use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class ConfirmablePasswordController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly AuthViewManager $views) {}

    public function show(Request $request): mixed
    {
        return $this->views->render(AuthViewManager::ConfirmPassword, $request);
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
