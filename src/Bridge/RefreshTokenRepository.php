<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Bridge;

use Bambamboole\LaravelOidc\Server\Token\RefreshToken as RefreshTokenModel;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new RefreshToken;
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
