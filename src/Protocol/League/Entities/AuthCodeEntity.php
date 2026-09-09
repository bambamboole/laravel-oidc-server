<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League\Entities;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class AuthCodeEntity implements AuthCodeEntityInterface
{
    use AuthCodeTrait, EntityTrait, TokenEntityTrait;
}
