<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League\Repositories;

use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\RefreshTokenEntity;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken as RefreshTokenModel;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new RefreshTokenEntity;
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        RefreshTokenModel::query()->forceCreate([
            'id' => $refreshTokenEntity->getIdentifier(),
            'access_token_id' => $refreshTokenEntity->getAccessToken()->getIdentifier(),
            'revoked' => false,
            'expires_at' => $refreshTokenEntity->getExpiryDateTime(),
        ]);
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        RefreshTokenModel::query()->whereKey($tokenId)->update(['revoked' => true]);
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        return RefreshTokenModel::query()->whereKey($tokenId)->where('revoked', false)->doesntExist();
    }
}
