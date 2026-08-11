<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Issuer;
use Illuminate\Http\JsonResponse;

/**
 * RFC 9728 protected resource metadata. Resources are declared in
 * `oidc.protected_resources`, keyed by their path relative to the issuer
 * origin; the `resource` value must byte-for-byte match the URL a client
 * derived the metadata URL from (RFC 9728 §3.3), so it is rebuilt from the
 * issuer, never from the request host.
 */
class ProtectedResourceController
{
    public function __invoke(string $path = ''): JsonResponse
    {
        $path = trim($path, '/');

        /** @var array<string, array{scopes?: array<int, string>}> $resources */
        $resources = config('oidc.protected_resources', []);

        abort_unless(array_key_exists($path, $resources), 404);

        return response()->json([
            'resource' => $path === '' ? Issuer::url() : Issuer::url().'/'.$path,
            'authorization_servers' => [Issuer::url()],
            'scopes_supported' => array_values($resources[$path]['scopes'] ?? []),
            'bearer_methods_supported' => ['header'],
        ])->header('Cache-Control', 'max-age=3600, public');
    }
}
