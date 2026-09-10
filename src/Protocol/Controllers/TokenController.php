<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Controllers;

use Bambamboole\LaravelOidc\Server\Protocol\TokenEndpoint;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class TokenController
{
    public function __construct(protected TokenEndpoint $endpoint) {}

    public function __invoke(Request $request): JsonResponse
    {
        return $this->endpoint->issue($request)->toResponse($request);
    }
}
