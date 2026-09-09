<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class BridgeScope implements ScopeEntityInterface
{
    use EntityTrait;

    public function __construct(string $identifier)
    {
        $this->setIdentifier($identifier);
    }

    public function jsonSerialize(): string
    {
        return $this->getIdentifier();
    }
}
