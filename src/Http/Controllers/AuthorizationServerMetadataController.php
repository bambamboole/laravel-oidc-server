<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Http\ProviderMetadata;
use Illuminate\Http\JsonResponse;

/**
 * RFC 8414 authorization server metadata, served under the path-insertion form
 * clients derive from an issuer with a path component (§3.1). The realm sits
 * behind the well-known segment and selects the document.
 */
class AuthorizationServerMetadataController
{
    public function __invoke(ProviderMetadata $metadata): JsonResponse
    {
        return response()->json($metadata->document())->header('Cache-Control', 'max-age=3600, public');
    }
}
