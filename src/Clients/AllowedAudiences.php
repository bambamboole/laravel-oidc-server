<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients;

use Bambamboole\LaravelOidc\Server\Models\Client;

/**
 * The per-client audience allowlist (`allowed_exchange_audiences`) governs
 * every audience-carrying grant: token exchange and client-credentials
 * `resource` requests alike.
 */
final class AllowedAudiences
{
    /** @return list<string> */
    public static function of(Client $client): array
    {
        return array_values(array_filter($client->allowed_exchange_audiences ?? [], is_string(...)));
    }
}
