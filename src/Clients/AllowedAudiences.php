<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients;

use Laravel\Passport\Client;

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
        $raw = $client->getRawOriginal('allowed_exchange_audiences');
        $decoded = is_string($raw) ? json_decode($raw, true) : null;

        return is_array($decoded) ? array_values(array_filter($decoded, is_string(...))) : [];
    }
}
