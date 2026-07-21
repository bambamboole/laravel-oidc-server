<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Bambamboole\LaravelOidc\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Auth\MultiFactor\TwoFactorManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ShowTwoFactorSecretKeyController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly TwoFactorManager $twoFactor) {}

    public function __invoke(Request $request): JsonResponse
    {
        $factor = $this->twoFactor->currentFactor($this->currentUser($request));

        abort_if($factor === null, 404, 'Two factor authentication has not been enabled.');

        return new JsonResponse(['secretKey' => $factor->secret]);
    }
}
