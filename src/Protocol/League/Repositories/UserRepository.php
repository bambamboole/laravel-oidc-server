<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;

/**
 * The provider enables no grant that authenticates a user by credentials at the
 * token endpoint, so this never resolves anyone.
 */
class UserRepository implements UserRepositoryInterface
{
    public function getUserEntityByUserCredentials(
        string $username,
        string $password,
        string $grantType,
        ClientEntityInterface $clientEntity,
    ): ?UserEntityInterface {
        return null;
    }
}
