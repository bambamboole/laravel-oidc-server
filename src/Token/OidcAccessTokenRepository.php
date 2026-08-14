<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Token;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\PersonalAccessTokenEvent;
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
        private readonly Auditor $auditor,
    ) {
        parent::__construct($events);
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        if ($accessTokenEntity instanceof OidcAccessToken) {
            $this->applyPersonalAccessTriggers($accessTokenEntity);
        }

        parent::persistNewAccessToken($accessTokenEntity);

        if ($accessTokenEntity instanceof OidcAccessToken && $this->isDirectPersonalAccessIssuance($accessTokenEntity)) {
            $this->auditor->log(AuditEventType::TokenIssued, userId: $accessTokenEntity->getUserIdentifier(), clientId: $accessTokenEntity->getClient()->getIdentifier(), context: [
                'grant_type' => 'personal_access',
                'jti' => $accessTokenEntity->getIdentifier(),
                'scopes' => array_values(array_map(
                    fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                    $accessTokenEntity->getScopes(),
                )),
            ]);
        }
    }

    /**
     * Every token issued at the token endpoint also passes persistence; those
     * requests always carry a grant_type input and are audited by their grant,
     * so only grant_type-less issuance (the personal access factory) is
     * audited here — otherwise a client holding both the personal_access and
     * another grant would double-log.
     */
    private function isDirectPersonalAccessIssuance(OidcAccessToken $token): bool
    {
        if (app()->bound('request') && app('request')->filled('grant_type')) {
            return false;
        }

        return $this->isPersonalAccessClient($token->getClient());
    }

    private function applyPersonalAccessTriggers(OidcAccessToken $token): void
    {
        $userIdentifier = $token->getUserIdentifier();

        if (! $this->pipeline->has('personal_access_token')
            || $userIdentifier === null
            || ! $this->isPersonalAccessClient($token->getClient())) {
            return;
        }

        $user = $this->resolveUser((string) $userIdentifier);

        if ($user === null) {
            return;
        }

        $api = $this->pipeline->run('personal_access_token', new PersonalAccessTokenEvent(
            user: $user,
            client: $token->getClient(),
            scopes: array_values(array_map(
                fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                $token->getScopes(),
            )),
        ));

        if ($api->isDenied()) {
            $this->auditor->log(AuditEventType::TokenIssuanceFailed, userId: (string) $userIdentifier, clientId: $token->getClient()->getIdentifier(), context: array_filter([
                'grant_type' => 'personal_access',
                'reason' => 'pipeline_denied',
                'deny_reason' => $api->denyReason(),
            ]));

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
