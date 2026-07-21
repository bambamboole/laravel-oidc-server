<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\MultiFactor\TotpFactorProvider;
use Bambamboole\LaravelOidc\Auth\MultiFactor\TwoFactorManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ShowTwoFactorQrCodeController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly TwoFactorManager $twoFactor,
        private readonly TotpFactorProvider $totp,
    ) {}

    /**
     * @return JsonResponse|array<never, never>
     */
    public function __invoke(Request $request): JsonResponse|array
    {
        $user = $this->currentUser($request);
        $factor = $this->twoFactor->currentFactor($user);

        if ($factor === null) {
            return [];
        }

        return new JsonResponse([
            'svg' => $this->totp->qrCodeSvg($factor, $user),
            'url' => $this->totp->qrCodeUrl($factor, $user),
        ]);
    }
}
