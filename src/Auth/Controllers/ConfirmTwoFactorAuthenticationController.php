<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\MultiFactor\TwoFactorManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class ConfirmTwoFactorAuthenticationController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly TwoFactorManager $twoFactor) {}

    public function __invoke(Request $request): JsonResponse|RedirectResponse
    {
        $request->validate(['code' => ['required', 'string']]);

        if (! $this->twoFactor->confirm($this->currentUser($request), $request->string('code')->value())) {
            throw ValidationException::withMessages([
                'code' => __('The provided two factor authentication code was invalid.'),
            ])->errorBag('confirmTwoFactorAuthentication');
        }

        return $this->statusResponse($request, 'two-factor-authentication-confirmed', 200);
    }
}
