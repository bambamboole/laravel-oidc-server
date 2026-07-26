<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns;

use Bambamboole\LaravelOidc\Server\Http\ClientCredentials;
use Bambamboole\LaravelOidc\Server\Http\OAuthError;
use Illuminate\Http\Request;

trait AuthenticatesConfidentialClient
{
    /**
     * @return array{string, string}
     */
    private function authenticateConfidentialClient(Request $request, ClientCredentials $credentials): array
    {
        $clientId = $credentials->validate($request);

        if ($clientId === null) {
            OAuthError::client();
        }

        return [$clientId, (string) $request->input('token')];
    }

    private function isRefreshTokenHint(Request $request): bool
    {
        return $request->input('token_type_hint') === 'refresh_token';
    }
}
