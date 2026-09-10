<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Grants;

use Bambamboole\LaravelOidc\Server\Authentication\Context\AuthenticationContextStore;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Contracts\Grant;
use Bambamboole\LaravelOidc\Server\Protocol\Http\Pkce;
use Bambamboole\LaravelOidc\Server\Protocol\TokenResponse;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeGrant;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Tokens\Events\TokenIssuanceFailed;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Bambamboole\LaravelOidc\Server\Tokens\TokenRevoker;
use Illuminate\Http\Request;

/**
 * OAuth 2.1 §4.1.3 with RFC 7636 verification. A code is single use: the
 * first redemption consumes it atomically, and any later one revokes every
 * token that descends from it (OAuth 2.1 §4.1.3, RFC 6749 §4.1.2).
 */
final readonly class AuthorizationCodeGrant implements Grant
{
    public const string TYPE = 'authorization_code';

    public function __construct(
        private InteractiveTokenIssuer $issuer,
        private ScopeGrant $scopes,
        private AuthenticationContextStore $contexts,
        private TokenRevoker $revoker,
    ) {}

    public function type(): string
    {
        return self::TYPE;
    }

    public function handle(Client $client, Request $request): TokenResponse
    {
        $code = $request->input('code');

        if (! is_string($code) || $code === '') {
            throw OAuthServerException::invalidRequest('The code parameter is missing.');
        }

        $authCode = AuthorizationCode::query()->inRealm()->find($code)
            ?? throw OAuthServerException::invalidGrant('The authorization code is invalid.');

        // Ownership before replay detection: only the client the code was
        // issued to can trigger the revocation of the chain it produced.
        if (! $authCode->issuedTo($client)) {
            throw OAuthServerException::invalidGrant('The authorization code was not issued to this client.');
        }

        if ($authCode->revoked) {
            $this->replayed($authCode, $client);
        }

        if ($authCode->expires_at === null || $authCode->expires_at->isPast()) {
            throw OAuthServerException::invalidGrant('The authorization code has expired.');
        }

        $this->verifyRedirectUri($authCode, $request);
        $this->verifyCodeVerifier($authCode, $request);

        // Consuming before minting makes the code single use under concurrent
        // redemptions: only the request that flips the flag proceeds.
        $consumed = AuthorizationCode::query()->whereKey($authCode->id)->where('revoked', false)->update(['revoked' => true]) === 1;

        if (! $consumed) {
            $this->replayed($authCode, $client);
        }

        $userId = (string) $authCode->user_id;
        $scopes = $this->scopes->finalize($authCode->scopes ?? [], self::TYPE, $client, $userId);
        $context = $authCode->context_id !== null ? $this->contexts->find($authCode->context_id) : null;

        return $this->issuer->issue(
            client: $client,
            userId: $userId,
            scopes: $scopes,
            grantType: self::TYPE,
            context: $context,
            nonce: $authCode->nonce,
            authTime: $authCode->auth_time,
            authCodeId: $authCode->id,
            withRefreshToken: $client->hasGrantType(RefreshTokenGrant::TYPE),
        );
    }

    private function verifyRedirectUri(AuthorizationCode $authCode, Request $request): void
    {
        if ($authCode->redirect_uri === null) {
            return;
        }

        $redirectUri = $request->input('redirect_uri');

        if (! is_string($redirectUri) || $redirectUri === '') {
            throw OAuthServerException::invalidRequest('The redirect_uri parameter is required when it was part of the authorization request.');
        }

        if (! hash_equals($authCode->redirect_uri, $redirectUri)) {
            throw OAuthServerException::invalidGrant('The redirect_uri does not match the authorization request.');
        }
    }

    private function verifyCodeVerifier(AuthorizationCode $authCode, Request $request): void
    {
        $verifier = $request->input('code_verifier');

        if (! is_string($verifier) || $verifier === '') {
            throw OAuthServerException::invalidRequest('The code_verifier parameter is missing.');
        }

        if (! Pkce::isWellFormed($verifier)) {
            throw OAuthServerException::invalidRequest('The code_verifier must follow RFC 7636 §4.1.');
        }

        if ($authCode->code_challenge_method !== Pkce::METHOD) {
            throw OAuthServerException::serverError("Unsupported code challenge method [{$authCode->code_challenge_method}].");
        }

        if (! Pkce::verify($verifier, $authCode->code_challenge)) {
            throw OAuthServerException::invalidGrant('Failed to verify the code_verifier.');
        }
    }

    private function replayed(AuthorizationCode $authCode, Client $client): never
    {
        $this->revoker->revokeChain($authCode->id);

        event(new TokenIssuanceFailed(
            grantType: self::TYPE,
            reason: 'code_replayed',
            clientId: $client->client_id,
            userId: (string) $authCode->user_id,
        ));

        throw OAuthServerException::invalidGrant('The authorization code has already been used.');
    }
}
