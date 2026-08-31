<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\Pipeline;

use League\OAuth2\Server\Entities\ClientEntityInterface;

final readonly class ClientCredentialsEvent
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $audiences  RFC 8707 `resource` values the token will be bound to
     */
    public function __construct(
        public ClientEntityInterface $client,
        public array $scopes,
        public array $audiences = [],
    ) {}
}
