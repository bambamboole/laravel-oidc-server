<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients;

use Illuminate\Http\Request;

final class ClientCredentials
{
    public function __construct(private readonly ClientRepository $clients) {}

    public function validate(Request $request): ?string
    {
        $clientId = $request->getUser() ?? $request->input('client_id');
        $clientSecret = $request->getPassword() ?? $request->input('client_secret');

        if ($clientId === null || $clientSecret === null) {
            return null;
        }

        $client = $this->clients->findActive($clientId);

        return $client !== null && $this->clients->validateSecret($client, $clientSecret) ? $clientId : null;
    }
}
