<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Controllers;

use Bambamboole\LaravelOidc\Server\Authentication\Actions\ConfirmPassword;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordConfirmationView;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

class ConfirmablePasswordController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly ConfirmPassword $confirm) {}

    /**
     * PasswordConfirmationView is resolved here (not via the constructor) so
     * store() — which shares this class — never eagerly resolves a view the
     * request doesn't render.
     */
    public function show(Request $request): Responsable|Response
    {
        return app(PasswordConfirmationView::class)->respond($request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        $request->validate(['password' => ['required', 'string']]);

        $user = $this->currentUser($request);

        if ($user === null || ! ($this->confirm)($user, $request->string('password')->value(), $request->session())) {
            throw ValidationException::withMessages(['password' => __('auth.password')]);
        }

        if ($request->wantsJson()) {
            return new JsonResponse('', 201);
        }

        return redirect()->intended($this->homeUrl());
    }
}
