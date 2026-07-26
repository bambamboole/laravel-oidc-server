<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Contracts;

use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Illuminate\Support\Collection;
use League\OAuth2\Server\Entities\ClientEntityInterface;

interface ScopeRepository
{
    /** @return Collection<int, Scope> */
    public function all(): Collection;

    public function find(string $identifier): ?Scope;

    /**
     * @param  Scope[]  $requested
     * @return Scope[]
     */
    public function finalize(array $requested, string $grantType, ClientEntityInterface $client, ?string $userIdentifier = null): array;
}
