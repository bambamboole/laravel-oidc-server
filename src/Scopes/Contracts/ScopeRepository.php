<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes\Contracts;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Illuminate\Support\Collection;

interface ScopeRepository
{
    /** @return Collection<int, Scope> */
    public function all(): Collection;

    public function find(string $identifier): ?Scope;

    /**
     * The last word on what a token gets: `$requested` is already limited to
     * known scopes the client is assigned, its default scopes included. Null
     * client means a grant without a registered client (hand-built tokens).
     *
     * @param  Scope[]  $requested
     * @return Scope[]
     */
    public function finalize(array $requested, string $grantType, ?Client $client, ?string $userIdentifier = null): array;
}
