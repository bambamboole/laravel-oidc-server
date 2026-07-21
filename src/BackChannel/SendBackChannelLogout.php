<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\BackChannel;

use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Bambamboole\LaravelOidc\Token\LogoutTokenBuilder;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Passport;

class SendBackChannelLogout implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    public int $tries = 3;

    public function __construct(
        public readonly string $sid,
        public readonly string $clientId,
    ) {}

    public function handle(SessionRegistry $registry, LogoutTokenBuilder $builder): void
    {
        $session = $registry->find($this->sid);
        $client = Passport::client()->newQuery()->find($this->clientId);

        if ($session === null || $client === null) {
            return;
        }

        $uri = $client->getRawOriginal('backchannel_logout_uri');
        if (! is_string($uri) || $uri === '') {
            return;
        }

        Http::asForm()->post($uri, ['logout_token' => $builder->build($session, $this->clientId)])->throw();
    }
}
