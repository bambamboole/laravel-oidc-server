<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Grant;

use Bambamboole\LaravelOidc\Auth\AccessTokenContextLink;
use Bambamboole\LaravelOidc\Auth\AuthenticationContextStore;
use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Bambamboole\LaravelOidc\Grant\Concerns\HasAuthenticationContextIssuance;
use Bambamboole\LaravelOidc\Responses\IdTokenResponse;
use DateInterval;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestRefreshTokenEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Fork of League\OAuth2\Server\Grant\RefreshTokenGrant::respondToAccessTokenRequest() (league v9), kept
 * byte-close except for the context resolution / deny-on-expiry / reissue block, so future league diffs
 * remain easy to port. Registered in place of Passport's stock refresh grant by grant identifier.
 */
class OidcRefreshTokenGrant extends RefreshTokenGrant
{
    use HasAuthenticationContextIssuance;

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        // Defense-in-depth: AuthorizationServer (and this grant) is a container singleton,
        // so under Octane it persists across requests. League's parent validates the
        // client, refresh token, and scopes *before* ever calling issueAccessToken() —
        // the only place pendingContext is normally cleared. If any of that validation
        // throws, a pendingContext set below would otherwise survive into the next
        // request. Clear it unconditionally at entry so a stale value never leaks.
        $this->pendingContext = null;

        $client = $this->validateClient($request);
        $oldRefreshToken = $this->validateOldRefreshToken($request, $client->getIdentifier());

        $scopes = $this->validateScopes(
            $this->getRequestParameter(
                'scope',
                $request,
                implode(self::SCOPE_DELIMITER_STRING, $oldRefreshToken['scopes'])
            )
        );

        foreach ($scopes as $scope) {
            if (in_array($scope->getIdentifier(), $oldRefreshToken['scopes'], true) === false) {
                throw OAuthServerException::invalidScope($scope->getIdentifier());
            }
        }

        $userId = $oldRefreshToken['user_id'];
        if (is_int($userId)) {
            $userId = (string) $userId;
        }

        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $userId);

        // --- OIDC: resolve the authentication context and enforce deny-on-expiry ---
        $this->applyAuthenticationContext($oldRefreshToken['access_token_id'], $responseType);

        // Expire old tokens
        $this->accessTokenRepository->revokeAccessToken($oldRefreshToken['access_token_id']);
        if ($this->revokeRefreshTokens) {
            $this->refreshTokenRepository->revokeRefreshToken($oldRefreshToken['refresh_token_id']);
        }

        // Issue and persist new access token (trait re-links + stamps access-token claims)
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $userId, $scopes);
        $this->getEmitter()->emit(new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken));
        $responseType->setAccessToken($accessToken);

        $refreshToken = $this->issueRefreshToken($accessToken);

        if ($refreshToken !== null) {
            $this->getEmitter()->emit(new RequestRefreshTokenEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request, $refreshToken));
            $responseType->setRefreshToken($refreshToken);
        }

        return $responseType;
    }

    private function applyAuthenticationContext(string $oldAccessTokenId, ResponseTypeInterface $responseType): void
    {
        $contextId = app(AccessTokenContextLink::class)->contextIdFor($oldAccessTokenId);

        if ($contextId === null) {
            // No context ever attached (non-interactive flow): refresh as a plain token.
            return;
        }

        $context = app(AuthenticationContextStore::class)->find($contextId);

        if ($context === null) {
            throw OAuthServerException::invalidRefreshToken('The authentication session has expired; re-authentication is required.');
        }

        if ($context->sid !== null) {
            $session = app(SessionRegistry::class)->find($context->sid);
            if ($session === null || ! $session->isActive()) {
                throw OAuthServerException::invalidRefreshToken('The authentication session has ended; re-authentication is required.');
            }
        } elseif ($context->expires_at !== null && $context->expires_at->isPast()) {
            // Pre-session context (no sid): fall back to the 2a-2 per-context cap.
            throw OAuthServerException::invalidRefreshToken('The authentication session has expired; re-authentication is required.');
        }

        $this->pendingContext = $context;

        if ($responseType instanceof IdTokenResponse) {
            $responseType->setAmr($context->amr);
            $responseType->setIdTokenClaims($context->id_token_claims);
            $responseType->setAuthTime($context->auth_time);
            $responseType->setSid($context->sid);
        }
    }
}
