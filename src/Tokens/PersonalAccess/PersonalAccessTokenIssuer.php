<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\PersonalAccess;

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeGrant;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Tokens\Events\TokenIssuanceFailed;
use Bambamboole\LaravelOidc\Server\Tokens\Events\TokenIssued;
use Bambamboole\LaravelOidc\Server\Tokens\Exceptions\TokenIssuanceDeniedException;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\PersonalAccessTokenEvent;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Mints personal access tokens directly rather than driving an internal request
 * through the authorization server, so the personal-access trigger runs here as
 * a normal step instead of hooking token persistence.
 */
final readonly class PersonalAccessTokenIssuer
{
    public const string GRANT_TYPE = 'personal_access';

    public function __construct(
        private ClientRepository $clients,
        private ScopeGrant $scopes,
        private AccessTokenMinter $minter,
        private AccessTokenPipeline $pipeline,
        private RealmResolver $realms,
    ) {}

    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $context
     */
    public function make(Authenticatable $user, string $name, array $scopes = [], array $context = []): PersonalAccessTokenResult
    {
        $client = $this->clients->personalAccessClient();
        $userId = (string) $user->getAuthIdentifier();

        $granted = $this->scopes->finalize($scopes, self::GRANT_TYPE, $client, $userId);

        $claims = $this->runTriggers($user, $client, $granted, $context);

        $token = $this->minter->mint(
            userId: $userId,
            clientId: $client->client_id,
            scopeIds: $granted,
            ttl: $this->realms->current()->tokens()->accessToken(),
            extraClaims: $claims,
        );

        event(new TokenIssued(
            grantType: self::GRANT_TYPE,
            jti: $token->jti,
            scopes: $granted,
            clientId: $client->client_id,
            userId: $userId,
        ));

        AccessToken::query()->whereKey($token->jti)->update([
            'name' => $name,
            'context' => $context === [] ? null : json_encode($context),
        ]);

        return new PersonalAccessTokenResult(
            accessToken: $token->jwt,
            token: AccessToken::query()->findOrFail($token->jti),
        );
    }

    /**
     * @param  list<string>  $granted
     * @param  array<string, mixed>  $context
     * @return array<string, mixed>
     */
    private function runTriggers(Authenticatable $user, Client $client, array $granted, array $context): array
    {
        if (! $this->pipeline->has('personal_access_token')) {
            return [];
        }

        $api = $this->pipeline->run('personal_access_token', new PersonalAccessTokenEvent(
            user: $user,
            client: $client,
            scopes: $granted,
            context: $context,
        ));

        if ($api->isDenied()) {
            event(new TokenIssuanceFailed(
                grantType: self::GRANT_TYPE,
                reason: 'pipeline_denied',
                clientId: $client->client_id,
                userId: (string) $user->getAuthIdentifier(),
                denyReason: $api->denyReason(),
            ));

            throw new TokenIssuanceDeniedException((string) $api->denyReason());
        }

        return $api->accessTokenClaims();
    }
}
