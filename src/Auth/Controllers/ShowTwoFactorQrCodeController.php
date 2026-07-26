<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Controllers;

use Bambamboole\LaravelOidc\Server\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\TotpFactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\TwoFactorManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ShowTwoFactorQrCodeController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly TwoFactorManager $twoFactor,
        private readonly TotpFactorProvider $totp,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $user = $this->currentUser($request);
        $factor = $this->twoFactor->currentFactor($user);

        abort_if($factor === null, 404, 'Two factor authentication has not been enabled.');

        return new JsonResponse([
            'svg' => $this->totp->qrCodeSvg($factor, $user),
            'url' => $this->totp->qrCodeUrl($factor, $user),
        ]);
    }
}
