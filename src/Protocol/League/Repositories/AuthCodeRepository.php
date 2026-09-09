<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League\Repositories;

use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\AuthCodeEntity;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ClientEntity;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthCode as AuthCodeModel;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;

class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCodeEntity;
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        AuthCodeModel::query()->forceCreate([
            'realm_id' => AuthCodeModel::currentRealm(),
            'id' => $authCodeEntity->getIdentifier(),
            'user_id' => $authCodeEntity->getUserIdentifier(),
            'client_id' => $this->storageKey($authCodeEntity->getClient()),
            'scopes' => array_map(
                fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                $authCodeEntity->getScopes(),
            ),
            'revoked' => false,
            'expires_at' => $authCodeEntity->getExpiryDateTime(),
        ]);
    }

    public function revokeAuthCode(string $codeId): void
    {
        AuthCodeModel::query()->whereKey($codeId)->update(['revoked' => true]);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        return AuthCodeModel::query()->whereKey($codeId)->where('revoked', false)->doesntExist();
    }

    protected function storageKey(ClientEntityInterface $client): string
    {
        return $client instanceof ClientEntity ? $client->storageKey() : $client->getIdentifier();
    }
}
