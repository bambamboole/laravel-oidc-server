<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Grant;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\ClientCredentialsEvent;
use Bambamboole\LaravelOidc\Server\Token\OidcAccessToken;
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
        private readonly Auditor $auditor,
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
        $api = $this->pipeline->run('client_credentials', $event);

        if ($api->isDenied()) {
            $this->auditor->log(AuditEventType::TokenIssuanceFailed, clientId: $client->getIdentifier(), context: array_filter([
                'grant_type' => $this->getIdentifier(),
                'reason' => 'pipeline_denied',
                'deny_reason' => $api->denyReason(),
            ]));

            throw OAuthServerException::accessDenied($api->denyReason());
        }

        $accessToken = parent::issueAccessToken($accessTokenTTL, $client, $userIdentifier, $scopes);

        if (! $accessToken instanceof OidcAccessToken) {
            throw new LogicException('The client-credentials grant requires an OIDC access token entity.');
        }

        foreach ($api->accessTokenClaims() as $name => $value) {
            $accessToken->addExtraClaim($name, $value);
        }

        $this->auditor->log(AuditEventType::TokenIssued, clientId: $client->getIdentifier(), context: [
            'grant_type' => $this->getIdentifier(),
            'jti' => $accessToken->getIdentifier(),
            'scopes' => $event->scopes,
        ]);

        return $accessToken;
    }
}
