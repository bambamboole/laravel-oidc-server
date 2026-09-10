<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Grants;

use Bambamboole\LaravelOidc\Server\Authentication\Context\AuthenticationContextStore;
use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Contracts\Grant;
use Bambamboole\LaravelOidc\Server\Protocol\Http\ScopeParameter;
use Bambamboole\LaravelOidc\Server\Protocol\TokenResponse;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeGrant;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\TokenRevoker;
use Illuminate\Http\Request;

/**
 * OAuth 2.1 §4.3. Refresh tokens rotate: each use revokes the presented token
 * and the access token it belongs to. A refresh is denied once the
 * authentication context it descends from has expired or its session ended,
 * so no token outlives the login that produced it.
 */
final readonly class RefreshTokenGrant implements Grant
{
    public const string TYPE = 'refresh_token';

    public function __construct(
        private InteractiveTokenIssuer $issuer,
        private ScopeGrant $scopes,
        private AuthenticationContextStore $contexts,
        private OidcSessionRepository $sessions,
        private TokenRevoker $revoker,
        private Auditor $auditor,
    ) {}

    public function type(): string
    {
        return self::TYPE;
    }

    public function handle(Client $client, Request $request): TokenResponse
    {
        $value = $request->input('refresh_token');

        if (! is_string($value) || $value === '') {
            throw OAuthServerException::invalidRequest('The refresh_token parameter is missing.');
        }

        $refreshToken = RefreshToken::query()
            ->inRealm()
            ->with('accessToken')
            ->find($value);
        $accessToken = $refreshToken?->accessToken;

        if ($refreshToken === null || $accessToken === null) {
            throw OAuthServerException::invalidGrant('The refresh token is invalid.');
        }

        if (! $accessToken->issuedTo($client)) {
            $this->auditor->log(AuditEventType::ClientAuthenticationFailed, clientId: $client->client_id, context: [
                'endpoint' => $request->path(),
                'reason' => 'refresh_token_client_mismatch',
            ]);

            throw OAuthServerException::invalidGrant('The refresh token was not issued to this client.');
        }

        if ($refreshToken->revoked) {
            if ($accessToken->auth_code_id !== null) {
                $this->revoker->revokeChain($accessToken->auth_code_id);
            }

            $this->deny('refresh_token_reused', 'The refresh token has been revoked.');
        }

        if ($refreshToken->expires_at === null || $refreshToken->expires_at->isPast()) {
            throw OAuthServerException::invalidGrant('The refresh token has expired.');
        }

        $userId = $accessToken->user_id;

        if ($userId === null || $userId === '') {
            throw OAuthServerException::invalidGrant('The refresh token is not bound to a user.');
        }

        $original = array_values($accessToken->scopes ?? []);
        $requested = ScopeParameter::parse($request->input('scope')) ?? $original;

        // OAuth 2.1 §4.3.1: the refreshed token may carry the original scopes or fewer.
        foreach ($requested as $scope) {
            if (! in_array($scope, $original, true)) {
                $this->auditor->log(AuditEventType::TokenIssuanceFailed, clientId: $client->client_id, context: [
                    'grant_type' => self::TYPE,
                    'reason' => 'scope_escalation',
                    'scope' => $scope,
                ]);

                throw OAuthServerException::invalidScope($scope);
            }
        }

        $scopes = $this->scopes->finalize($requested, self::TYPE, $client, (string) $userId);
        $context = $this->activeContext($accessToken);

        $this->revoker->revoke($accessToken->id);

        return $this->issuer->issue(
            client: $client,
            userId: (string) $userId,
            scopes: $scopes,
            grantType: self::TYPE,
            context: $context,
            nonce: null,
            authTime: $context?->auth_time,
            authCodeId: $accessToken->auth_code_id,
            withRefreshToken: true,
        );
    }

    /**
     * Null when the token never carried a context (a non-interactive chain);
     * otherwise the context must still be alive.
     */
    private function activeContext(AccessToken $accessToken): ?AuthenticationContext
    {
        $contextId = $accessToken->context_id;

        if ($contextId === null) {
            return null;
        }

        $context = $this->contexts->find($contextId)
            ?? $this->deny('context_expired', 'The authentication session has expired; re-authentication is required.');

        if ($context->sid !== null) {
            $session = $this->sessions->find($context->sid);

            if (! $session instanceof OidcSession || ! $session->isActive()) {
                $this->deny('session_ended', 'The authentication session has ended; re-authentication is required.', $context->sid);
            }
        } elseif ($context->expires_at !== null && $context->expires_at->isPast()) {
            $this->deny('context_expired', 'The authentication session has expired; re-authentication is required.');
        }

        return $context;
    }

    private function deny(string $reason, string $message, ?string $sid = null): never
    {
        $this->auditor->log(AuditEventType::TokenIssuanceFailed, sid: $sid, context: [
            'grant_type' => self::TYPE,
            'reason' => $reason,
        ]);

        throw OAuthServerException::invalidGrant($message);
    }
}
