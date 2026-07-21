<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http;

use Illuminate\Http\Request;
use Laravel\Passport\Bridge\ClientRepository;

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

        return $this->clients->validateClient($clientId, $clientSecret, null) ? $clientId : null;
    }
}
