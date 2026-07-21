<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\MultiFactor\TwoFactorManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

class RegenerateRecoveryCodesController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly TwoFactorManager $twoFactor) {}

    public function __invoke(Request $request): JsonResponse|RedirectResponse
    {
        $this->twoFactor->regenerateRecoveryCodes($this->currentUser($request));

        return $this->statusResponse($request, 'recovery-codes-generated', 200);
    }
}
