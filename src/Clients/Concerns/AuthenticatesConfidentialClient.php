<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Concerns;

use Bambamboole\LaravelOidc\Server\Clients\ClientCredentials;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthError;
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
            $attempted = $request->input('client_id');
            app(Auditor::class)->log(AuditEventType::ClientAuthenticationFailed, clientId: is_string($attempted) ? $attempted : null, context: [
                'endpoint' => $request->path(),
            ]);

            OAuthError::client();
        }

        return [$clientId, (string) $request->input('token')];
    }

    private function isRefreshTokenHint(Request $request): bool
    {
        return $request->input('token_type_hint') === 'refresh_token';
    }
}
