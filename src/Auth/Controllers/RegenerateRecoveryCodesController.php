<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Controllers;

use Bambamboole\LaravelOidc\Server\Auth\Controllers\Concerns\ResolvesIdentityGuard;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\RecoveryCodeProvider;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

class RegenerateRecoveryCodesController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly RecoveryCodeProvider $recoveryCodes) {}

    public function __invoke(Request $request): JsonResponse|RedirectResponse
    {
        $this->recoveryCodes->generate($this->currentUser($request));

        return $this->statusResponse($request, 'recovery-codes-generated', 200);
    }
}
