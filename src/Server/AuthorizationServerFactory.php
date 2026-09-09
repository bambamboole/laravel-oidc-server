<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Server;

use Bambamboole\LaravelOidc\Server\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Responses\IdTokenResponse;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

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
    ) {}

    public function make(): AuthorizationServer
    {
        return new AuthorizationServer(
            $this->clients,
            $this->accessTokens,
            $this->scopes,
            new CryptKey($this->keys->signingKey()->privateKey(), null, false),
            $this->encryptionKey->value(),
            $this->responseType,
        );
    }
}
