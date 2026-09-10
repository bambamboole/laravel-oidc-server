<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\BackChannel;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Sessions\LogoutTokenBuilder;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Support\Facades\Http;

class SendBackChannelLogout implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    public int $tries = 3;

    /** @param  string  $clientKey  the client's primary key, as recorded on the session participant */
    public function __construct(
        public readonly string $sid,
        public readonly string $clientKey,
    ) {}

    public function handle(OidcSessionRepository $registry, LogoutTokenBuilder $builder): void
    {
        $session = $registry->find($this->sid);
        $client = Client::query()->find($this->clientKey);

        if (! $session instanceof OidcSession || $client === null) {
            return;
        }

        $uri = $client->getRawOriginal('backchannel_logout_uri');
        if (! is_string($uri) || $uri === '') {
            return;
        }

        Http::asForm()->post($uri, ['logout_token' => $builder->build($session, $client->client_id)])->throw();
    }
}
