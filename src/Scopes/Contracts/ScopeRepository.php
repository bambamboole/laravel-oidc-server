<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes\Contracts;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Illuminate\Support\Collection;

/**
 * Every lookup is bound to the resources the request asks for: a scope only
 * exists under the audiences that own it. An empty `$audiences` means the
 * realm's default audience, its issuer URL — the same convention the token
 * minter follows.
 */
interface ScopeRepository
{
    /**
     * @param  list<string>  $audiences
     * @return Collection<int, Scope>
     */
    public function all(array $audiences = []): Collection;

    /** @param  list<string>  $audiences */
    public function find(string $identifier, array $audiences = []): ?Scope;

    /**
     * The last word on what a token gets: `$requested` is already limited to
     * known scopes the client is assigned, its default scopes included. Null
     * client means a grant without a registered client (hand-built tokens).
     *
     * @param  Scope[]  $requested
     * @param  list<string>  $audiences
     * @return Scope[]
     */
    public function finalize(array $requested, string $grantType, ?Client $client, ?string $userIdentifier = null, array $audiences = []): array;
}
