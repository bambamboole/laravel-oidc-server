<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Authentication\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Authentication\Context\AuthenticationContextStore;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Protocol\League\Grants\OidcAuthCodeGrant;
use Bambamboole\LaravelOidc\Server\Protocol\League\Grants\OidcClientCredentialsGrant;
use Bambamboole\LaravelOidc\Server\Protocol\League\Grants\OidcRefreshTokenGrant;
use Bambamboole\LaravelOidc\Server\Protocol\League\Grants\TokenExchangeGrant;
use Bambamboole\LaravelOidc\Server\Protocol\League\Repositories\AuthCodeRepository;
use Bambamboole\LaravelOidc\Server\Protocol\League\Repositories\RefreshTokenRepository;
use Bambamboole\LaravelOidc\Server\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Tokens\Context\AccessTokenContextLink;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\TokenExchanger;
use DateInterval;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestEvent;

/**
 * Builds the league server per request rather than once: the signing key is read
 * at construction, so a server pinned for the process lifetime would keep signing
 * with a rotated-out key until the workers restart.
 */
final readonly class AuthorizationServerFactory
{
    public function __construct(
        private ClientRepositoryInterface $clients,
        private AccessTokenRepositoryInterface $accessTokens,
        private ScopeRepositoryInterface $scopes,
        private SigningKeys $keys,
        private EncryptionKey $encryptionKey,
        private IdTokenResponse $responseType,
        private RealmResolver $realms,
        private ClientRepository $clientModels,
        private AuthCodeRepository $authCodes,
        private RefreshTokenRepository $refreshTokens,
        private AccessTokenContextLink $contextLink,
        private AccessTokenPipeline $pipeline,
        private AuthenticationContextStore $contexts,
        private OidcSessionRepository $sessions,
        private AuthSessionState $sessionState,
        private Auditor $auditor,
        private TokenExchanger $exchanger,
    ) {}

    public function make(): AuthorizationServer
    {
        $server = new AuthorizationServer(
            $this->clients,
            $this->accessTokens,
            $this->scopes,
            new CryptKey($this->keys->signingKey()->privateKey(), null, false),
            $this->encryptionKey->value(),
            $this->responseType,
        );

        $this->enableGrants($server);
        $this->auditClientAuthenticationFailures($server);

        return $server;
    }

    private function enableGrants(AuthorizationServer $server): void
    {
        $realm = $this->realms->current();
        $accessTokenTtl = $realm->tokens()->accessToken();

        $authCodeGrant = new OidcAuthCodeGrant(
            $this->authCodes,
            $this->refreshTokens,
            new DateInterval('PT10M'),
            $this->contextLink,
            $this->pipeline,
            $this->contexts,
            $this->sessions,
            $this->sessionState,
            $this->auditor,
            $this->realms,
            $this->clientModels,
        );
        $authCodeGrant->setRefreshTokenTTL($realm->tokens()->refreshToken());
        $server->enableGrantType($authCodeGrant, $accessTokenTtl);

        $refreshGrant = new OidcRefreshTokenGrant(
            $this->refreshTokens,
            $this->contextLink,
            $this->pipeline,
            $this->contexts,
            $this->sessions,
            $this->auditor,
            $this->clientModels,
        );
        $refreshGrant->setRefreshTokenTTL($realm->tokens()->refreshToken());
        $server->enableGrantType($refreshGrant, $accessTokenTtl);

        $server->enableGrantType(
            new OidcClientCredentialsGrant($this->pipeline, $this->auditor, $this->clientModels),
            $realm->tokens()->clientCredentials(),
        );

        if ($realm->clients()->tokenExchange) {
            $server->enableGrantType(new TokenExchangeGrant($this->exchanger), $accessTokenTtl);
        }
    }

    private function auditClientAuthenticationFailures(AuthorizationServer $server): void
    {
        $listener = function (RequestEvent $event): void {
            $body = $event->getRequest()->getParsedBody();
            $clientId = is_array($body) ? ($body['client_id'] ?? null) : null;
            $clientId = is_string($clientId) ? $clientId : ($event->getRequest()->getQueryParams()['client_id'] ?? null);

            $this->auditor->log(AuditEventType::ClientAuthenticationFailed, clientId: is_string($clientId) ? $clientId : null, context: [
                'endpoint' => trim($event->getRequest()->getUri()->getPath(), '/'),
                'reason' => $event->eventName(),
            ]);
        };

        $server->getEmitter()->subscribeTo(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $listener);
        $server->getEmitter()->subscribeTo(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $listener);
    }
}
