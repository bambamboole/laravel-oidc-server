<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Pipeline;

use Illuminate\Contracts\Auth\Authenticatable;
use League\OAuth2\Server\Entities\ClientEntityInterface;

final readonly class PersonalAccessTokenEvent
{
    /** @param list<string> $scopes */
    public function __construct(
        public Authenticatable $user,
        public ClientEntityInterface $client,
        public array $scopes,
    ) {}
}
