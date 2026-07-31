<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Controllers;

use Bambamboole\LaravelOidc\Server\Auth\PasswordConfirmation;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ShowConfirmedPasswordStatusController
{
    public function __invoke(Request $request): JsonResponse
    {
        return new JsonResponse([
            'confirmed' => PasswordConfirmation::confirmedRecently($request->session()),
        ]);
    }
}
