<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Clients;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Illuminate\Http\Request;

/**
 * RFC 6749 §2.3.1 client authentication at the token endpoint: HTTP Basic
 * (client_secret_basic) or body credentials (client_secret_post). A public
 * client presents no secret; a confidential one must present the hashed one.
 */
final readonly class ClientAuthenticator
{
    public function __construct(
        private ClientRepository $clients,
        private Auditor $auditor,
    ) {}

    public function authenticate(Request $request, string $grantType): Client
    {
        $clientId = $request->getUser() ?? $request->input('client_id');
        $clientSecret = $request->getPassword() ?? $request->input('client_secret');

        if (! is_string($clientId) || $clientId === '') {
            throw OAuthServerException::invalidRequest('The client_id parameter is missing.');
        }

        $client = $this->clients->findActive($clientId)
            ?? $this->fail($request, $clientId, 'unknown_client');

        if (! $this->clients->validateSecret($client, is_string($clientSecret) ? $clientSecret : null)) {
            $this->fail($request, $clientId, 'invalid_secret');
        }

        if (! $client->hasGrantType($grantType)) {
            throw OAuthServerException::unauthorizedClient('The client is not authorized to use this grant type.');
        }

        return $client;
    }

    private function fail(Request $request, string $clientId, string $reason): never
    {
        $this->auditor->log(AuditEventType::ClientAuthenticationFailed, clientId: $clientId, context: [
            'endpoint' => $request->path(),
            'reason' => $reason,
        ]);

        throw OAuthServerException::invalidClient();
    }
}
