<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League\Entities;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;

class UserEntity implements UserEntityInterface
{
    use EntityTrait;

    public function __construct(string $identifier)
    {
        $this->setIdentifier($identifier);
    }
}
