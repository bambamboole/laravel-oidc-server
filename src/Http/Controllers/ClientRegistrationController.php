<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Laravel\Passport\ClientRepository;

/**
 * RFC 7591 dynamic client registration. Registers public (secret-less)
 * authorization-code clients — PKCE is enforced by the grant for every
 * client. Unknown metadata fields are ignored per RFC 7591 §2, since MCP
 * clients routinely send `application_type`, `software_id`, and similar.
 */
class ClientRegistrationController
{
    public function __invoke(Request $request, ClientRepository $clients): JsonResponse
    {
        $redirectUris = $request->input('redirect_uris');

        if (! is_array($redirectUris) || $redirectUris === []) {
            return $this->error('invalid_client_metadata', 'At least one redirect URI is required.');
        }

        $normalized = [];

        foreach ($redirectUris as $uri) {
            if (! is_string($uri) || trim($uri) === '') {
                return $this->error('invalid_redirect_uri', 'Redirect URIs must be non-empty strings.');
            }

            $uri = trim($uri);
            $rejection = $this->rejectRedirectUri($uri);

            if ($rejection !== null) {
                return $this->error('invalid_redirect_uri', $rejection);
            }

            $normalized[$uri] = $uri;
        }

        $normalized = array_values($normalized);

        $client = $clients->createAuthorizationCodeGrantClient(
            $this->clientName($request, $normalized),
            $normalized,
            confidential: false,
        );

        /** @var array<int, string> $scopes */
        $scopes = array_values(config('oidc.dcr.default_scopes', []));

        if ($scopes !== []) {
            $client->forceFill(['scopes' => $scopes])->save();
        }

        $response = [
            'client_id' => (string) $client->getKey(),
            'client_id_issued_at' => Carbon::now()->getTimestamp(),
            'client_secret_expires_at' => 0,
            'client_name' => (string) $client->getAttribute('name'),
            'redirect_uris' => $normalized,
            'grant_types' => $client->getAttribute('grant_types'),
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ];

        if ($scopes !== []) {
            $response['scope'] = implode(' ', $scopes);
        }

        return response()->json($response, 201);
    }

    /**
     * @param  array<int, string>  $redirectUris
     */
    private function clientName(Request $request, array $redirectUris): string
    {
        foreach (['client_name', 'name'] as $key) {
            $name = $request->input($key);

            if (is_string($name) && trim($name) !== '') {
                return trim($name);
            }
        }

        $host = parse_url($redirectUris[0], PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : 'Dynamically Registered Client';
    }

    private function rejectRedirectUri(string $uri): ?string
    {
        $parts = parse_url($uri);

        if (preg_match('/[\x00-\x20\x7F\\\\]|%(?![0-9A-Fa-f]{2})/', $uri) === 1
            || ! is_array($parts)
            || isset($parts['user'])
            || isset($parts['pass'])
            || array_key_exists('fragment', $parts)) {
            return "The redirect URI [{$uri}] must be an absolute URI without user information or a fragment.";
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));

        if ($scheme === '' || $host === '') {
            return "The redirect URI [{$uri}] must declare a scheme and a host.";
        }

        if (! in_array($scheme, ['http', 'https'], true)) {
            /** @var array<int, string> $schemes */
            $schemes = config('oidc.dcr.allowed_redirect_schemes', []);

            return in_array($scheme, array_map(strtolower(...), $schemes), true)
                ? null
                : "The redirect URI scheme [{$scheme}] is not allowed.";
        }

        /** @var array<int, string> $domains */
        $domains = config('oidc.dcr.allowed_redirect_domains', ['*']);

        if (in_array('*', $domains, true) || in_array($host, array_map(strtolower(...), $domains), true)) {
            return null;
        }

        return "The redirect URI host [{$host}] is not allowed.";
    }

    private function error(string $error, string $description): JsonResponse
    {
        return response()->json([
            'error' => $error,
            'error_description' => $description,
        ], 400);
    }
}
