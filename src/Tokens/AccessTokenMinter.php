<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use DateInterval;

/**
 * Mints and persists an RFC 9068 access token outside a grant flow (session
 * tokens, personal access tokens, token exchange). The protocol layer binds
 * the league-backed implementation; nothing in the Tokens domain sees league.
 */
interface AccessTokenMinter
{
    /**
     * @param  list<string>  $scopeIds
     * @param  list<string>  $audiences
     * @param  array<string, mixed>  $extraClaims
     * @param  array<string, mixed>|null  $actor  the RFC 8693 `act` claim, when the token is issued on behalf of another party
     */
    public function mint(
        ?string $userId,
        Client $client,
        array $scopeIds,
        DateInterval $ttl,
        array $audiences = [],
        array $extraClaims = [],
        ?array $actor = null,
    ): MintedAccessToken;
}
