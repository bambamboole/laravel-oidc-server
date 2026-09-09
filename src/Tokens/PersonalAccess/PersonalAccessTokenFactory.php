<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\PersonalAccess;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PersonalAccessTokenEvent;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ClientEntity;
use Bambamboole\LaravelOidc\Server\Protocol\League\Repositories\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use DateInterval;
use Illuminate\Contracts\Auth\Authenticatable;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;

/**
 * Mints personal access tokens directly rather than driving an internal request
 * through the authorization server, so the personal-access trigger runs here as
 * a normal step instead of hooking token persistence.
 */
final readonly class PersonalAccessTokenFactory
{
    public const string GRANT_TYPE = 'personal_access';

    public function __construct(
        private ClientRepository $clients,
        private ScopeRepository $scopes,
        private AccessTokenMinter $minter,
        private AccessTokenPipeline $pipeline,
        private Auditor $auditor,
    ) {}

    /** @param  list<string>  $scopes */
    public function make(Authenticatable $user, string $name, array $scopes = []): PersonalAccessTokenResult
    {
        $client = $this->clients->personalAccessClient();
        $userId = (string) $user->getAuthIdentifier();

        $entity = new ClientEntity(
            identifier: $client->client_id,
            name: $client->name,
            redirectUri: $client->redirect_uris,
            isConfidential: $client->confidential(),
            key: $client->getKey(),
            provider: $client->provider,
            grantTypes: $client->grant_types,
        );

        $granted = array_map(
            fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $this->scopes->finalizeScopes(
                array_values(array_filter(array_map(
                    fn (string $id): ?ScopeEntityInterface => $this->scopes->getScopeEntityByIdentifier($id),
                    $scopes,
                ))),
                self::GRANT_TYPE,
                $entity,
                $userId,
            ),
        );

        $claims = $this->runTriggers($user, $entity, $granted);

        $token = $this->minter->mint(
            userId: $userId,
            client: $client,
            scopeIds: $granted,
            ttl: new DateInterval('PT'.(int) config('oidc.token_lifetimes.access_token').'S'),
            extraClaims: $claims,
        );

        $this->auditor->log(AuditEventType::TokenIssued, userId: $userId, clientId: $client->client_id, context: [
            'grant_type' => self::GRANT_TYPE,
            'jti' => $token->getIdentifier(),
            'scopes' => $granted,
        ]);

        Token::query()->whereKey($token->getIdentifier())->update(['name' => $name]);

        return new PersonalAccessTokenResult(
            accessToken: $token->toString(),
            token: Token::query()->findOrFail($token->getIdentifier()),
        );
    }

    /**
     * @param  list<string>  $granted
     * @return array<string, mixed>
     */
    private function runTriggers(Authenticatable $user, ClientEntity $client, array $granted): array
    {
        if (! $this->pipeline->has('personal_access_token')) {
            return [];
        }

        $api = $this->pipeline->run('personal_access_token', new PersonalAccessTokenEvent(
            user: $user,
            client: $client,
            scopes: $granted,
        ));

        if ($api->isDenied()) {
            $this->auditor->log(AuditEventType::TokenIssuanceFailed, userId: (string) $user->getAuthIdentifier(), clientId: $client->getIdentifier(), context: array_filter([
                'grant_type' => self::GRANT_TYPE,
                'reason' => 'pipeline_denied',
                'deny_reason' => $api->denyReason(),
            ]));

            throw OAuthServerException::accessDenied($api->denyReason());
        }

        return $api->accessTokenClaims();
    }
}
