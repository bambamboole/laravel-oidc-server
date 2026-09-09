<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Actions;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Clients\ClientRegistrationException;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;

/**
 * RFC 7591 dynamic client registration. Registers public (secret-less)
 * authorization-code clients — PKCE is enforced by the grant for every
 * client. Unknown metadata fields are ignored per RFC 7591 §2, since MCP
 * clients routinely send `application_type`, `software_id`, and similar.
 */
final class RegisterClient
{
    public function __construct(
        private readonly ClientRepository $clients,
        private readonly Auditor $auditor,
        private readonly RealmResolver $realms,
    ) {}

    /**
     * @param  array<string, mixed>  $metadata  the RFC 7591 client metadata document
     *
     * @throws ClientRegistrationException
     */
    public function __invoke(array $metadata): Client
    {
        $redirectUris = $this->normalizedRedirectUris($metadata['redirect_uris'] ?? null);

        $client = $this->clients->createAuthorizationCodeGrantClient(
            $this->clientName($metadata, $redirectUris),
            $redirectUris,
            confidential: false,
        );

        $scopes = $this->realms->current()->clients()->defaultScopes;

        if ($scopes !== []) {
            $client->forceFill(['scopes' => $scopes])->save();
        }

        $this->auditor->log(AuditEventType::ClientRegistered, clientId: (string) $client->getKey(), context: [
            'client_name' => (string) $client->getAttribute('name'),
            'redirect_uris' => $redirectUris,
        ]);

        return $client;
    }

    /**
     * @return array<int, string>
     */
    private function normalizedRedirectUris(mixed $redirectUris): array
    {
        if (! is_array($redirectUris) || $redirectUris === []) {
            throw new ClientRegistrationException('invalid_client_metadata', 'At least one redirect URI is required.');
        }

        $normalized = [];

        foreach ($redirectUris as $uri) {
            if (! is_string($uri) || trim($uri) === '') {
                throw new ClientRegistrationException('invalid_redirect_uri', 'Redirect URIs must be non-empty strings.');
            }

            $uri = trim($uri);
            $rejection = $this->rejectRedirectUri($uri);

            if ($rejection !== null) {
                throw new ClientRegistrationException('invalid_redirect_uri', $rejection);
            }

            $normalized[$uri] = $uri;
        }

        return array_values($normalized);
    }

    /**
     * @param  array<string, mixed>  $metadata
     * @param  array<int, string>  $redirectUris
     */
    private function clientName(array $metadata, array $redirectUris): string
    {
        foreach (['client_name', 'name'] as $key) {
            $name = $metadata[$key] ?? null;

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
            $schemes = $this->realms->current()->clients()->allowedRedirectSchemes;

            return in_array($scheme, array_map(strtolower(...), $schemes), true)
                ? null
                : "The redirect URI scheme [{$scheme}] is not allowed.";
        }

        $domains = $this->realms->current()->clients()->allowedRedirectDomains;

        if (in_array('*', $domains, true) || in_array($host, array_map(strtolower(...), $domains), true)) {
            return null;
        }

        return "The redirect URI host [{$host}] is not allowed.";
    }
}
