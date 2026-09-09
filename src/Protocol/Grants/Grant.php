<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Grants;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Protocol\TokenResponse;
use Illuminate\Http\Request;

/**
 * One grant_type the token endpoint answers. The endpoint has already
 * authenticated the client and checked that it may use this grant.
 */
interface Grant
{
    public function type(): string;

    public function handle(Client $client, Request $request): TokenResponse;
}
