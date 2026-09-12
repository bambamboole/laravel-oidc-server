<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Purge;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;

/**
 * Deletes a client and everything the package issued to it. Tokens, codes,
 * consents and session participations all carry a foreign key to the client
 * and cascade with it.
 */
final readonly class PurgeClient
{
    public function __invoke(Client $client): void
    {
        $client->delete();
    }
}
