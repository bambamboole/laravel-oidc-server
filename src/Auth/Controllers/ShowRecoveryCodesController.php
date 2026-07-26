<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Controllers;

use Bambamboole\LaravelOidc\Server\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\TwoFactorManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ShowRecoveryCodesController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly TwoFactorManager $twoFactor) {}

    public function __invoke(Request $request): JsonResponse
    {
        $user = $this->currentUser($request);

        abort_if($this->twoFactor->currentFactor($user) === null, 404, 'Two factor authentication has not been enabled.');

        return new JsonResponse($this->twoFactor->recoveryCodes($user));
    }
}
