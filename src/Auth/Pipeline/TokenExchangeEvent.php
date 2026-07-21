<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Pipeline;

use Illuminate\Contracts\Auth\Authenticatable;
use League\OAuth2\Server\Entities\ClientEntityInterface;

final readonly class TokenExchangeEvent
{
    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $subjectClaims
     */
    public function __construct(
        public Authenticatable $user,
        public ClientEntityInterface $client,
        public array $scopes,
        public string $audience,
        public array $subjectClaims,
    ) {}
}
