<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\UserActionManager;
use Bambamboole\LaravelOidc\Auth\Views\RegisterPrompt;
use Bambamboole\LaravelOidc\Auth\Views\RegisterView;
use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class RegisteredUserController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly UserActionManager $actions,
    ) {}

    /**
     * RegisterView is resolved here (not via the constructor) so store() —
     * which shares this class — never eagerly resolves a view the request
     * doesn't render.
     */
    public function create(Request $request): Responsable|Response
    {
        return app(RegisterView::class)->respond(new RegisterPrompt, $request);
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
