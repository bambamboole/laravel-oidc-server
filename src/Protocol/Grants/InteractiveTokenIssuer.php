<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Grants;

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Protocol\TokenResponse;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\MintedAccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Concerns\ResolvesTokenUser;
use Bambamboole\LaravelOidc\Server\Tokens\Events\TokenIssuanceFailed;
use Bambamboole\LaravelOidc\Server\Tokens\Events\TokenIssued;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenBuilder;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenRequest;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AuthorizationCodeEvent;
use DateTimeImmutable;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Issues the token set of an interactive grant (authorization code and its
 * refreshes): the access token stamped with the authentication context's
 * claims and linked to it, the rotated refresh token, and the id_token.
 *
 * Authorization-code triggers run before anything is persisted (a deny stops
 * issuance) and their claims are stamped after the context's, so a trigger
 * can override a stale login-time claim.
 */
final readonly class InteractiveTokenIssuer
{
    use ResolvesTokenUser;

    public function __construct(
        private AccessTokenMinter $minter,
        private AccessTokenPipeline $pipeline,
        private IdTokenBuilder $idTokens,
        private RealmResolver $realms,
    ) {}

    /**
     * @param  list<string>  $scopes
     * @param  string|null  $authCodeId  the code this token descends from, so a replayed code or refresh token can revoke the whole chain
     * @param  list<string>  $audiences  RFC 8707 resources the token is for; empty for the realm default
     */
    public function issue(
        Client $client,
        string $userId,
        array $scopes,
        string $grantType,
        ?AuthenticationContext $context,
        ?string $nonce,
        ?int $authTime,
        ?string $authCodeId,
        bool $withRefreshToken,
        array $audiences = [],
    ): TokenResponse {
        $api = $this->runTriggers($client, $userId, $scopes, $grantType);

        if ($api?->isDenied() === true) {
            event(new TokenIssuanceFailed(
                grantType: $grantType,
                reason: 'pipeline_denied',
                clientId: $client->client_id,
                userId: $userId,
                denyReason: $api->denyReason(),
            ));

            throw OAuthServerException::accessDenied($api->denyReason());
        }

        $tokens = $this->realms->current()->tokens();

        $accessToken = $this->minter->mint(
            $userId,
            $client->client_id,
            $scopes,
            $tokens->accessToken(),
            audiences: $audiences,
            extraClaims: [...($context instanceof AuthenticationContext ? $context->access_token_claims : []), ...($api?->accessTokenClaims() ?? [])],
        );

        if ($context instanceof AuthenticationContext || $authCodeId !== null) {
            AccessToken::query()->whereKey($accessToken->jti)->update([
                'auth_code_id' => $authCodeId,
                'context_id' => $context?->id,
            ]);
        }

        $refreshToken = $withRefreshToken ? $this->issueRefreshToken($accessToken) : null;

        $idToken = in_array('openid', $scopes, true)
            ? $this->idTokens->build(new IdTokenRequest(
                userId: $userId,
                clientId: $client->client_id,
                scopes: $scopes,
                accessToken: $accessToken->jwt,
                nonce: $nonce,
                authTime: $authTime,
                amr: $context instanceof AuthenticationContext ? $context->amr : [],
                idTokenClaims: $context instanceof AuthenticationContext ? $context->id_token_claims : [],
                sid: $context?->session_id,
            ))
            : null;

        event(new TokenIssued(
            grantType: $grantType,
            jti: $accessToken->jti,
            scopes: $scopes,
            clientId: $client->client_id,
            userId: $userId,
            sid: $context?->session_id,
            audiences: $audiences,
        ));

        return new TokenResponse($accessToken, $refreshToken, $idToken);
    }

    /**
     * @param  list<string>  $scopes
     */
    private function runTriggers(Client $client, string $userId, array $scopes, string $grantType): ?AccessTokenApi
    {
        if (! $this->pipeline->has('authorization_code')) {
            return null;
        }

        $user = $this->resolveUser($userId);

        if (! $user instanceof Authenticatable) {
            return null;
        }

        return $this->pipeline->run('authorization_code', new AuthorizationCodeEvent(
            user: $user,
            client: $client,
            scopes: $scopes,
            grantType: $grantType,
        ));
    }

    private function issueRefreshToken(MintedAccessToken $accessToken): string
    {
        $id = bin2hex(random_bytes(40));

        RefreshToken::query()->forceCreate([
            'realm_id' => $this->realms->current()->identifier(),
            'id' => $id,
            'access_token_id' => $accessToken->jti,
            'expires_at' => (new DateTimeImmutable)->add($this->realms->current()->tokens()->refreshToken()),
        ]);

        return $id;
    }
}
