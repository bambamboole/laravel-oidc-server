<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Tokens;

use DateInterval;

/**
 * Mints and persists an RFC 9068 access token: for the token endpoint's
 * grants as well as outside a grant flow (session tokens, personal access
 * tokens, token exchange).
 */
interface AccessTokenMinter
{
    /**
     * @param  string  $clientId  the wire client_id of an active client in the current realm
     * @param  list<string>  $scopeIds
     * @param  list<string>  $audiences
     * @param  array<string, mixed>  $extraClaims
     * @param  array<string, mixed>|null  $actor  the RFC 8693 `act` claim, when the token is issued on behalf of another party
     */
    public function mint(
        ?string $userId,
        string $clientId,
        array $scopeIds,
        DateInterval $ttl,
        array $audiences = [],
        array $extraClaims = [],
        ?array $actor = null,
    ): MintedAccessToken;
}
