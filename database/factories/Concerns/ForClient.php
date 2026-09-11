<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories\Concerns;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;

/**
 * Unlike for(), this also moves the row into the client's realm, where
 * everything issued to the client lives.
 */
trait ForClient
{
    public function forClient(Client $client): static
    {
        return $this->state(['client_id' => $client->getKey(), 'realm_id' => $client->realm_id]);
    }
}
