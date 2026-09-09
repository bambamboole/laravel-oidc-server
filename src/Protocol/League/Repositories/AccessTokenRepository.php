<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League\Repositories;

use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ClientEntity;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\OidcAccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    /** @param  array<int, ScopeEntityInterface>  $scopes */
    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null,
    ): AccessTokenEntityInterface {
        return new OidcAccessToken($userIdentifier, $scopes, $clientEntity);
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        Token::query()->forceCreate([
            'realm_id' => Token::currentRealm(),
            'id' => $accessTokenEntity->getIdentifier(),
            'user_id' => $accessTokenEntity->getUserIdentifier(),
            'client_id' => $this->storageKey($accessTokenEntity->getClient()),
            'scopes' => array_map(
                fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                $accessTokenEntity->getScopes(),
            ),
            'revoked' => false,
            'expires_at' => $accessTokenEntity->getExpiryDateTime(),
        ]);
    }

    public function revokeAccessToken(string $tokenId): void
    {
        Token::query()->whereKey($tokenId)->update(['revoked' => true]);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return Token::query()->whereKey($tokenId)->where('revoked', false)->doesntExist();
    }

    protected function storageKey(ClientEntityInterface $client): string
    {
        return $client instanceof ClientEntity ? $client->storageKey() : $client->getIdentifier();
    }
}
