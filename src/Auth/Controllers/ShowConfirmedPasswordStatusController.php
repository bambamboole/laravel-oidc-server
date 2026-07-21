<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ShowConfirmedPasswordStatusController
{
    public function __invoke(Request $request): JsonResponse
    {
        $confirmedAt = (int) $request->session()->get('auth.password_confirmed_at', 0);

        $confirmed = (time() - $confirmedAt) < (int) config('auth.password_timeout', 900);

        return new JsonResponse(['confirmed' => $confirmed]);
    }
}
