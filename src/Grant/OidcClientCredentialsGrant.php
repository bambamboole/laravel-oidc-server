<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Grant;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\ClientCredentialsEvent;
use Bambamboole\LaravelOidc\Server\Clients\AllowedAudiences;
use Bambamboole\LaravelOidc\Server\Token\OidcAccessToken;
use DateInterval;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

class OidcClientCredentialsGrant extends ClientCredentialsGrant
{
    /**
     * League's built-in factories use error codes 2-14; this is chosen well outside that range
     * so it never collides with an upstream code the client might switch on.
     */
    private const INVALID_TARGET_ERROR_CODE = 900;

    /** @var list<string> */
    private array $requestedAudiences = [];

    public function __construct(
        private readonly AccessTokenPipeline $pipeline,
        private readonly Auditor $auditor,
    ) {}

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL,
    ): ResponseTypeInterface {
        $this->requestedAudiences = $this->requestedResources($request);

        try {
            return parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
        } finally {
            $this->requestedAudiences = [];
        }
    }

    /**
     * @param  ScopeEntityInterface[]  $scopes
     */
    protected function issueAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        ?string $userIdentifier,
        array $scopes = [],
    ): AccessTokenEntityInterface {
        $this->assertAudiencesAllowed($client);

        $event = new ClientCredentialsEvent(
            client: $client,
            scopes: array_values(array_map(
                fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                $scopes,
            )),
            audiences: $this->requestedAudiences,
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

        if ($this->requestedAudiences !== []) {
            $accessToken->setAudience(...$this->requestedAudiences);
        }

        foreach ($api->accessTokenClaims() as $name => $value) {
            $accessToken->addExtraClaim($name, $value);
        }

        $this->auditor->log(AuditEventType::TokenIssued, clientId: $client->getIdentifier(), context: array_filter([
            'grant_type' => $this->getIdentifier(),
            'jti' => $accessToken->getIdentifier(),
            'scopes' => $event->scopes,
            'audiences' => $this->requestedAudiences,
        ]));

        return $accessToken;
    }

    /**
     * RFC 8707 `resource` parameters: each value must be an absolute URI
     * without a fragment; one value or a list is accepted.
     *
     * @return list<string>
     */
    private function requestedResources(ServerRequestInterface $request): array
    {
        $body = (array) $request->getParsedBody();
        $raw = $body['resource'] ?? [];
        $resources = array_values(is_array($raw) ? $raw : [$raw]);

        foreach ($resources as $resource) {
            if (! is_string($resource)
                || ! filter_var($resource, FILTER_VALIDATE_URL)
                || str_contains($resource, '#')) {
                throw $this->invalidTarget('The resource parameter must be an absolute URI without a fragment.');
            }
        }

        /** @var list<string> $resources */
        return array_values(array_unique($resources));
    }

    private function assertAudiencesAllowed(ClientEntityInterface $client): void
    {
        if ($this->requestedAudiences === []) {
            return;
        }

        $model = Passport::client()->newQuery()->find($client->getIdentifier());
        $allowed = $model instanceof Client ? AllowedAudiences::of($model) : [];

        if (array_diff($this->requestedAudiences, $allowed) !== []) {
            throw $this->invalidTarget('The requested resource is not permitted for this client.');
        }
    }

    private function invalidTarget(string $message): OAuthServerException
    {
        return new OAuthServerException($message, self::INVALID_TARGET_ERROR_CODE, 'invalid_target', 400);
    }
}
