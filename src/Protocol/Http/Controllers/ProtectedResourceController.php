<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\RealmAudiences;
use Illuminate\Http\JsonResponse;

/**
 * RFC 9728 protected resource metadata. Resources are declared in
 * `oidc.protected_resources`, keyed by their path relative to the issuer
 * origin; the `resource` value must byte-for-byte match the URL a client
 * derived the metadata URL from (RFC 9728 §3.3), so it is the identifier
 * {@see RealmAudiences} derives from the issuer — never the request host —
 * and is one of the audiences the realm's bearer guard accepts.
 */
class ProtectedResourceController
{
    public function __invoke(IssuerResolver $issuer, RealmAudiences $audiences, string $path = ''): JsonResponse
    {
        $path = trim($path, '/');

        /** @var array<string, array{scopes?: array<int, string>}> $resources */
        $resources = config('oidc.protected_resources', []);

        abort_unless(array_key_exists($path, $resources), 404);

        return response()->json([
            'resource' => $audiences->protectedResource($path),
            'authorization_servers' => [$issuer->url()],
            'scopes_supported' => array_values($resources[$path]['scopes'] ?? []),
            'bearer_methods_supported' => ['header'],
        ])->header('Cache-Control', 'max-age=3600, public');
    }
}
