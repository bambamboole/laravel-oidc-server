<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Grant;

use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Auth\Pipeline\ClientCredentialsEvent;
use Bambamboole\LaravelOidc\Token\OidcAccessToken;
use DateInterval;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use LogicException;

class OidcClientCredentialsGrant extends ClientCredentialsGrant
{
    public function __construct(
        private readonly AccessTokenPipeline $pipeline,
    ) {}

    /**
     * @param  ScopeEntityInterface[]  $scopes
     */
    protected function issueAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        ?string $userIdentifier,
        array $scopes = [],
    ): AccessTokenEntityInterface {
        $event = new ClientCredentialsEvent(
            client: $client,
            scopes: array_values(array_map(
                fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                $scopes,
            )),
        );
        $api = $this->pipeline->runClientCredentials($event);

        if ($api->isDenied()) {
            throw OAuthServerException::accessDenied($api->denyReason());
        }

        $accessToken = parent::issueAccessToken($accessTokenTTL, $client, $userIdentifier, $scopes);

        if (! $accessToken instanceof OidcAccessToken) {
            throw new LogicException('The client-credentials grant requires an OIDC access token entity.');
        }

        foreach ($api->accessTokenClaims() as $name => $value) {
            $accessToken->addExtraClaim($name, $value);
        }

        return $accessToken;
    }
}
