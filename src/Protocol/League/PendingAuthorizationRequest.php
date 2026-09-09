<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League;

use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PendingAuthorization;
use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Illuminate\Http\Request;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;

/**
 * Reads the league authorization request the authorize endpoint stashed in
 * the session back out for the post-login pipeline.
 */
final class PendingAuthorizationRequest implements PendingAuthorization
{
    public function __construct(private readonly ClientRepository $clients) {}

    public function client(Request $request): ?Client
    {
        $authRequest = $this->stashed($request);

        return $authRequest === null ? null : $this->clients->findActive($authRequest->getClient()->getIdentifier());
    }

    public function scopes(Request $request): array
    {
        $authRequest = $this->stashed($request);

        return $authRequest === null ? [] : array_values(array_map(
            fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $authRequest->getScopes(),
        ));
    }

    private function stashed(Request $request): ?AuthorizationRequestInterface
    {
        $authRequest = $request->session()->get('authRequest');

        return $authRequest instanceof AuthorizationRequestInterface ? $authRequest : null;
    }
}
