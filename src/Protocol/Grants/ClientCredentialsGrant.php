<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Grants;

use Bambamboole\LaravelOidc\Server\Clients\AllowedAudiences;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Contracts\Grant;
use Bambamboole\LaravelOidc\Server\Protocol\Http\ResourceParameter;
use Bambamboole\LaravelOidc\Server\Protocol\Http\ScopeParameter;
use Bambamboole\LaravelOidc\Server\Protocol\TokenResponse;
use Bambamboole\LaravelOidc\Server\Scopes\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeGrant;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\RealmAudiences;
use Bambamboole\LaravelOidc\Server\Tokens\Events\TokenIssuanceFailed;
use Bambamboole\LaravelOidc\Server\Tokens\Events\TokenIssued;
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
        private RealmResolver $realms,
        private RealmAudiences $audiences,
    ) {}

    public function type(): string
    {
        return self::TYPE;
    }

    public function handle(Client $client, Request $request): TokenResponse
    {
        $resources = ResourceParameter::parse($request->input('resource'));
        $this->assertAudiencesAllowed($client, $resources);

        $audiences = $this->audiences->resolve($resources);
        $requested = ScopeParameter::parse($request->input('scope')) ?? [];

        foreach ($requested as $scope) {
            if ($scope !== '*' && (! $this->scopes->find($scope, $audiences) instanceof Scope || ! $client->allowsScope($scope, $audiences))) {
                throw OAuthServerException::invalidScope($scope);
            }
        }

        $scopes = $this->scopeGrant->finalize($requested, self::TYPE, $client, audiences: $audiences);

        $api = $this->pipeline->run(self::TYPE, new ClientCredentialsEvent(
            client: $client,
            scopes: $scopes,
            audiences: $resources,
        ));

        if ($api->isDenied()) {
            event(new TokenIssuanceFailed(
                grantType: self::TYPE,
                reason: 'pipeline_denied',
                clientId: $client->client_id,
                denyReason: $api->denyReason(),
            ));

            throw OAuthServerException::accessDenied($api->denyReason());
        }

        $token = $this->minter->mint(
            null,
            $client->client_id,
            $scopes,
            $this->realms->current()->tokens()->clientCredentials(),
            $resources,
            $api->accessTokenClaims(),
        );

        event(new TokenIssued(
            grantType: self::TYPE,
            jti: $token->jti,
            scopes: $scopes,
            clientId: $client->client_id,
            audiences: $resources,
        ));

        return new TokenResponse($token);
    }

    /** @param  list<string>  $audiences */
    private function assertAudiencesAllowed(Client $client, array $audiences): void
    {
        if ($audiences !== [] && array_diff($audiences, AllowedAudiences::of($client)) !== []) {
            throw OAuthServerException::invalidTarget('The requested resource is not permitted for this client.');
        }
    }
}
