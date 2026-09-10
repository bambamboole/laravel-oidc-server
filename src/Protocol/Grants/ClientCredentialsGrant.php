<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Grants;

use Bambamboole\LaravelOidc\Server\Clients\AllowedAudiences;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Contracts\Grant;
use Bambamboole\LaravelOidc\Server\Protocol\Http\ScopeParameter;
use Bambamboole\LaravelOidc\Server\Protocol\TokenResponse;
use Bambamboole\LaravelOidc\Server\Scopes\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeGrant;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\ClientCredentialsEvent;
use Illuminate\Http\Request;

/**
 * OAuth 2.1 §4.2, with RFC 8707 `resource` parameters bounding the audience.
 */
final readonly class ClientCredentialsGrant implements Grant
{
    public const string TYPE = 'client_credentials';

    public function __construct(
        private AccessTokenMinter $minter,
        private AccessTokenPipeline $pipeline,
        private ScopeRepository $scopes,
        private ScopeGrant $scopeGrant,
        private Auditor $auditor,
        private RealmResolver $realms,
    ) {}

    public function type(): string
    {
        return self::TYPE;
    }

    public function handle(Client $client, Request $request): TokenResponse
    {
        $audiences = $this->requestedResources($request);
        $this->assertAudiencesAllowed($client, $audiences);

        $requested = ScopeParameter::parse($request->input('scope')) ?? [];

        foreach ($requested as $scope) {
            if ($scope !== '*' && (! $this->scopes->find($scope) instanceof Scope || ! $client->allowsScope($scope))) {
                throw OAuthServerException::invalidScope($scope);
            }
        }

        $scopes = $this->scopeGrant->finalize($requested, self::TYPE, $client);

        $api = $this->pipeline->run(self::TYPE, new ClientCredentialsEvent(
            client: $client,
            scopes: $scopes,
            audiences: $audiences,
        ));

        if ($api->isDenied()) {
            $this->auditor->log(AuditEventType::TokenIssuanceFailed, clientId: $client->client_id, context: array_filter([
                'grant_type' => self::TYPE,
                'reason' => 'pipeline_denied',
                'deny_reason' => $api->denyReason(),
            ]));

            throw OAuthServerException::accessDenied($api->denyReason());
        }

        $token = $this->minter->mint(
            null,
            $client->client_id,
            $scopes,
            $this->realms->current()->tokens()->clientCredentials(),
            $audiences,
            $api->accessTokenClaims(),
        );

        $this->auditor->log(AuditEventType::TokenIssued, clientId: $client->client_id, context: array_filter([
            'grant_type' => self::TYPE,
            'jti' => $token->jti,
            'scopes' => $scopes,
            'audiences' => $audiences,
        ]));

        return new TokenResponse($token);
    }

    /**
     * RFC 8707 `resource` parameters: each value must be an absolute URI
     * without a fragment; one value or a list is accepted.
     *
     * @return list<string>
     */
    private function requestedResources(Request $request): array
    {
        $raw = $request->input('resource') ?? [];
        $resources = array_values(is_array($raw) ? $raw : [$raw]);

        foreach ($resources as $resource) {
            if (! is_string($resource)
                || ! filter_var($resource, FILTER_VALIDATE_URL)
                || str_contains($resource, '#')) {
                throw OAuthServerException::invalidTarget('The resource parameter must be an absolute URI without a fragment.');
            }
        }

        /** @var list<string> $resources */
        return array_values(array_unique($resources));
    }

    /** @param  list<string>  $audiences */
    private function assertAudiencesAllowed(Client $client, array $audiences): void
    {
        if ($audiences !== [] && array_diff($audiences, AllowedAudiences::of($client)) !== []) {
            throw OAuthServerException::invalidTarget('The requested resource is not permitted for this client.');
        }
    }
}
