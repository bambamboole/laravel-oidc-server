<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Purge;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Consents\Models\Consent;
use Bambamboole\LaravelOidc\Server\Sessions\Models\SessionParticipant;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Illuminate\Support\Facades\DB;

/**
 * Deletes a client and everything the package issued to it. The rows name the
 * client without a foreign key, so nothing cascades on its own.
 */
final readonly class PurgeClient
{
    public function __invoke(Client $client): void
    {
        $key = (string) $client->getKey();

        DB::transaction(function () use ($client, $key): void {
            RefreshToken::query()
                ->whereIn('access_token_id', AccessToken::query()->where('client_id', $key)->select('id'))
                ->delete();
            AccessToken::query()->where('client_id', $key)->delete();
            AuthorizationCode::query()->where('client_id', $key)->delete();
            Consent::query()->where('client_id', $key)->delete();
            SessionParticipant::query()->where('client_id', $key)->delete();

            $client->delete();
        });
    }
}
