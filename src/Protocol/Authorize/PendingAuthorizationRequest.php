<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Authorize;

use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PendingAuthorization;
use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Illuminate\Http\Request;

/**
 * Reads the authorization request the authorize endpoint stashed in the
 * session back out for the post-login pipeline.
 */
final readonly class PendingAuthorizationRequest implements PendingAuthorization
{
    public function __construct(
        private AuthorizeRequestSession $session,
        private ClientRepository $clients,
    ) {}

    public function client(Request $request): ?Client
    {
        $authorizeRequest = $this->session->peek($request);

        return $authorizeRequest === null ? null : $this->clients->findActive($authorizeRequest->clientId);
    }

    public function scopes(Request $request): array
    {
        $authorizeRequest = $this->session->peek($request);

        return $authorizeRequest === null ? [] : $authorizeRequest->scopes;
    }
}
