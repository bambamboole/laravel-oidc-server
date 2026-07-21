<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\MultiFactor\TwoFactorManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ShowRecoveryCodesController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly TwoFactorManager $twoFactor) {}

    /**
     * @return JsonResponse|array<never, never>
     */
    public function __invoke(Request $request): JsonResponse|array
    {
        $user = $this->currentUser($request);

        if ($this->twoFactor->currentFactor($user) === null) {
            return [];
        }

        return new JsonResponse($this->twoFactor->recoveryCodes($user));
    }
}
