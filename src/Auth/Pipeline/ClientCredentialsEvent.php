<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Pipeline;

use League\OAuth2\Server\Entities\ClientEntityInterface;

final readonly class ClientCredentialsEvent
{
    /** @param list<string> $scopes */
    public function __construct(
        public ClientEntityInterface $client,
        public array $scopes,
    ) {}
}
