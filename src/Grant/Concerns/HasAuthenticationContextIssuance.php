<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Grant\Concerns;

use Bambamboole\LaravelOidc\Auth\AccessTokenContextLink;
use Bambamboole\LaravelOidc\Auth\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Auth\Pipeline\AuthorizationCodeEvent;
use Bambamboole\LaravelOidc\Token\OidcAccessToken;
use Bambamboole\LaravelOidc\Token\ResolvesTokenUser;
use DateInterval;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;

/**
 * Shared with OidcAuthCodeGrant and OidcRefreshTokenGrant: after league mints + persists the access
 * token, decorate it with the context's access-token claims and record the token→context link. The
 * pending context is set per request by the grant and read-and-cleared here (Octane-safe).
 *
 * Authorization-code triggers run before issuance (deny stops persistence) and their claims are
 * stamped after the context's, so a trigger can override a stale login-time claim.
 */
trait HasAuthenticationContextIssuance
{
    use ResolvesTokenUser;

    protected ?AuthenticationContext $pendingContext = null;

    /**
     * @param  list<ScopeEntityInterface>  $scopes
     */
    protected function issueAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        ?string $userIdentifier,
        array $scopes = []
    ): AccessTokenEntityInterface {
        $api = $this->runAuthorizationCodeTriggers($client, $userIdentifier, $scopes);

        if ($api?->isDenied() === true) {
            throw OAuthServerException::accessDenied($api->denyReason());
        }

        $accessToken = parent::issueAccessToken($accessTokenTTL, $client, $userIdentifier, $scopes);

        $context = $this->pendingContext;
        $this->pendingContext = null;

        if ($context !== null && $accessToken instanceof OidcAccessToken) {
            foreach ($context->access_token_claims as $name => $value) {
                $accessToken->addExtraClaim((string) $name, $value);
            }

            app(AccessTokenContextLink::class)->link($accessToken->getIdentifier(), $context->id);
        }

        if ($api !== null && $accessToken instanceof OidcAccessToken) {
            foreach ($api->accessTokenClaims() as $name => $value) {
                $accessToken->addExtraClaim($name, $value);
            }
        }

        return $accessToken;
    }

    /**
     * @param  list<ScopeEntityInterface>  $scopes
     */
    private function runAuthorizationCodeTriggers(
        ClientEntityInterface $client,
        ?string $userIdentifier,
        array $scopes,
    ): ?AccessTokenApi {
        $pipeline = app(AccessTokenPipeline::class);

        if (! $pipeline->hasAuthorizationCodeTriggers()) {
            return null;
        }

        $user = $this->resolveUser($userIdentifier);

        if ($user === null) {
            return null;
        }

        return $pipeline->runAuthorizationCode(new AuthorizationCodeEvent(
            user: $user,
            client: $client,
            scopes: array_map(
                fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                $scopes,
            ),
            grantType: $this->getIdentifier(),
        ));
    }
}
