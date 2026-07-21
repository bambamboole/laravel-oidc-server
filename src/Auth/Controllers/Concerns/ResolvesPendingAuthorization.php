<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Controllers\Concerns;

use Illuminate\Http\Request;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;

/**
 * Reads the OAuth authorization request a login was initiated from (if any),
 * so the post-login pipeline can see the pending client and scopes.
 */
trait ResolvesPendingAuthorization
{
    private function pendingClient(Request $request): ?ClientEntityInterface
    {
        $authRequest = $request->session()->get('authRequest');

        return $authRequest instanceof AuthorizationRequestInterface ? $authRequest->getClient() : null;
    }

    /**
     * @return list<string>
     */
    private function pendingScopes(Request $request): array
    {
        $authRequest = $request->session()->get('authRequest');

        if (! $authRequest instanceof AuthorizationRequestInterface) {
            return [];
        }

        return array_values(array_map(
            fn ($scope): string => $scope->getIdentifier(),
            $authRequest->getScopes(),
        ));
    }
}
