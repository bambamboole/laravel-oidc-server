<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\AuthViewManager;
use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\UserActionManager;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class RegisteredUserController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly AuthViewManager $views,
        private readonly UserActionManager $actions,
    ) {}

    public function create(Request $request): mixed
    {
        return $this->views->render(AuthViewManager::Register, $request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        $input = array_merge($request->all(), [
            'email' => $request->string('email')->lower()->value(),
        ]);

        event(new Registered($user = $this->actions->createUser($input)));

        Auth::guard($this->guardName())->login($user);

        if ($request->hasSession()) {
            $request->session()->regenerate();
        }

        if ($request->wantsJson()) {
            return new JsonResponse('', 201);
        }

        return redirect()->intended($this->homeUrl());
    }
}
