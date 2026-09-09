<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League\Grants\Concerns;

use Bambamboole\LaravelOidc\Server\Authentication\Context\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\AccessTokenEntity;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Tokens\Context\AccessTokenContextLink;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\ResolvesTokenUser;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AuthorizationCodeEvent;
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

    /** Assigned in the constructor of every grant composing this trait. */
    protected readonly AccessTokenContextLink $contextLink;

    /** Assigned in the constructor of every grant composing this trait. */
    protected readonly AccessTokenPipeline $accessTokenPipeline;

    /** Assigned in the constructor of every grant composing this trait. */
    protected readonly Auditor $auditor;

    /** Assigned in the constructor of every grant composing this trait. */
    protected readonly ClientRepository $clientModels;

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
            $this->auditor->log(AuditEventType::TokenIssuanceFailed, userId: $userIdentifier, clientId: $client->getIdentifier(), context: array_filter([
                'grant_type' => $this->getIdentifier(),
                'reason' => 'pipeline_denied',
                'deny_reason' => $api->denyReason(),
            ]));

            throw OAuthServerException::accessDenied($api->denyReason());
        }

        $accessToken = parent::issueAccessToken($accessTokenTTL, $client, $userIdentifier, $scopes);

        $context = $this->pendingContext;
        $this->pendingContext = null;

        if ($context !== null && $accessToken instanceof AccessTokenEntity) {
            foreach ($context->access_token_claims as $name => $value) {
                $accessToken->addExtraClaim((string) $name, $value);
            }

            $this->contextLink->link($accessToken->getIdentifier(), $context->id);
        }

        if ($api !== null && $accessToken instanceof AccessTokenEntity) {
            foreach ($api->accessTokenClaims() as $name => $value) {
                $accessToken->addExtraClaim($name, $value);
            }
        }

        $this->auditor->log(AuditEventType::TokenIssued, userId: $userIdentifier, clientId: $client->getIdentifier(), sid: $context?->sid, context: [
            'grant_type' => $this->getIdentifier(),
            'jti' => $accessToken->getIdentifier(),
            'scopes' => array_map(fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(), $scopes),
        ]);

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
        $pipeline = $this->accessTokenPipeline;

        if (! $pipeline->has('authorization_code')) {
            return null;
        }

        $user = $this->resolveUser($userIdentifier);
        $model = $this->clientModels->findActive($client->getIdentifier());

        if ($user === null || $model === null) {
            return null;
        }

        return $pipeline->run('authorization_code', new AuthorizationCodeEvent(
            user: $user,
            client: $model,
            scopes: array_map(
                fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                $scopes,
            ),
            grantType: $this->getIdentifier(),
        ));
    }
}
