<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Http\ProviderMetadata;
use Illuminate\Http\JsonResponse;

/**
 * RFC 8414 authorization server metadata. The optional `{path}` suffix covers
 * the path-insertion form clients derive from an issuer with a path component
 * (RFC 8414 §3.1); this issuer's metadata is the same document either way.
 */
class AuthorizationServerMetadataController
{
    public function __invoke(ProviderMetadata $metadata): JsonResponse
    {
        return response()->json($metadata->document())->header('Cache-Control', 'max-age=3600, public');
    }
}
