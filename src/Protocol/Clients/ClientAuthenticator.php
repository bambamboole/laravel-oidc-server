<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Clients;

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\Enums\TokenEndpointAuthMethod;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Events\ClientAuthenticationFailed;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Http\Request;

/**
 * RFC 6749 §2.3.1 client authentication for the token, introspection and
 * revocation endpoints. The client must use exactly the method it is
 * registered for: HTTP Basic (client_secret_basic), body credentials
 * (client_secret_post), or none for a public client. Presenting more than
 * one method is an invalid request.
 */
final readonly class ClientAuthenticator
{
    public function __construct(
        private ClientRepository $clients,
        private Hasher $hasher,
    ) {}

    /**
     * @param  string|null  $grantType  when given, the client must also be registered for this grant
     */
    public function authenticate(Request $request, ?string $grantType = null): Client
    {
        [$clientId, $secret, $method] = $this->credentials($request);

        $client = $this->clients->findActive($clientId)
            ?? $this->fail($request, $clientId, 'unknown_client');

        if ($client->token_endpoint_auth_method !== $method) {
            $this->fail($request, $clientId, 'auth_method_mismatch');
        }

        if ($method->requiresSecret() && ! $this->secretMatches($client, $secret)) {
            $this->fail($request, $clientId, 'invalid_secret');
        }

        if ($grantType !== null && ! $client->hasGrantType($grantType)) {
            throw OAuthServerException::unauthorizedClient('The client is not authorized to use this grant type.');
        }

        return $client;
    }

    /**
     * Basic credentials are form-urlencoded before base64 (RFC 6749 §2.3.1).
     *
     * @return array{string, ?string, TokenEndpointAuthMethod}
     */
    private function credentials(Request $request): array
    {
        $basicUser = $request->getUser();
        $bodyClientId = $request->input('client_id');
        $bodySecret = $request->input('client_secret');

        if ($basicUser !== null) {
            if (is_string($bodySecret) && $bodySecret !== '') {
                throw OAuthServerException::invalidRequest('The client used more than one authentication method.');
            }

            $clientId = urldecode($basicUser);

            if (is_string($bodyClientId) && $bodyClientId !== '' && $bodyClientId !== $clientId) {
                throw OAuthServerException::invalidRequest('The client_id parameter does not match the Authorization header.');
            }

            return [$clientId, urldecode((string) $request->getPassword()), TokenEndpointAuthMethod::ClientSecretBasic];
        }

        if (! is_string($bodyClientId) || $bodyClientId === '') {
            throw OAuthServerException::invalidClient('No client authentication included.');
        }

        if (is_string($bodySecret) && $bodySecret !== '') {
            return [$bodyClientId, $bodySecret, TokenEndpointAuthMethod::ClientSecretPost];
        }

        return [$bodyClientId, null, TokenEndpointAuthMethod::None];
    }

    private function secretMatches(Client $client, ?string $secret): bool
    {
        $hash = $client->getAttributes()['secret'] ?? null;

        return $secret !== null && $secret !== '' && is_string($hash) && $hash !== '' && $this->hasher->check($secret, $hash);
    }

    private function fail(Request $request, string $clientId, string $reason): never
    {
        event(new ClientAuthenticationFailed($request->path(), $reason, $clientId));

        throw OAuthServerException::invalidClient();
    }
}
