<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Controllers;

use Bambamboole\LaravelOidc\Server\Protocol\ProviderMetadata;
use Illuminate\Http\JsonResponse;

class DiscoveryController
{
    public function __invoke(ProviderMetadata $metadata): JsonResponse
    {
        return response()->json($metadata->document())->header('Cache-Control', 'max-age=3600, public');
    }
}
