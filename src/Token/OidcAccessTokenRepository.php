<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Token;

use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Auth\Pipeline\PersonalAccessTokenEvent;
use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;

/**
 * Passport's PersonalAccessTokenFactory dispatches an internal PSR-7 request
 * that never reaches the bound Laravel request, so there is no grant seam to
 * run personal-access triggers from. Persistence is the one package-owned
 * point every personal access token passes before serialization; tokens of
 * clients without the personal_access grant are left untouched.
 */
class OidcAccessTokenRepository extends AccessTokenRepository
{
    use ResolvesTokenUser;

    public function __construct(
        Dispatcher $events,
        private readonly AccessTokenPipeline $pipeline,
    ) {
        parent::__construct($events);
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        if ($accessTokenEntity instanceof OidcAccessToken) {
            $this->applyPersonalAccessTriggers($accessTokenEntity);
        }

        parent::persistNewAccessToken($accessTokenEntity);
    }

    private function applyPersonalAccessTriggers(OidcAccessToken $token): void
    {
        $userIdentifier = $token->getUserIdentifier();

        if (! $this->pipeline->hasPersonalAccessTokenTriggers()
            || $userIdentifier === null
            || ! $this->isPersonalAccessClient($token->getClient())) {
            return;
        }

        $user = $this->resolveUser((string) $userIdentifier);

        if ($user === null) {
            return;
        }

        $api = $this->pipeline->runPersonalAccessToken(new PersonalAccessTokenEvent(
            user: $user,
            client: $token->getClient(),
            scopes: array_values(array_map(
                fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                $token->getScopes(),
            )),
        ));

        if ($api->isDenied()) {
            throw OAuthServerException::accessDenied($api->denyReason());
        }

        foreach ($api->accessTokenClaims() as $name => $value) {
            $token->addExtraClaim($name, $value);
        }
    }

    private function isPersonalAccessClient(ClientEntityInterface $client): bool
    {
        $model = Passport::client()->newQuery()->find($client->getIdentifier());

        return $model !== null
            && in_array('personal_access', (array) $model->getAttribute('grant_types'), true);
    }
}
