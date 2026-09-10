<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\BackChannel;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;

class BackChannelLogoutNotifier
{
    public function __construct(private readonly OidcSessionRepository $registry) {}

    public function notify(string $sid): void
    {
        $session = $this->registry->find($sid);

        if ($session === null || $session->logout_notified_at !== null) {
            return;
        }

        $clientKeys = $this->registry->participantClientIds($sid);

        if ($clientKeys !== []) {
            $notifiable = Client::query()
                ->whereIn('id', $clientKeys)
                ->whereNotNull('backchannel_logout_uri')
                ->pluck('id');

            foreach ($notifiable as $clientKey) {
                SendBackChannelLogout::dispatch($sid, (string) $clientKey);
            }
        }

        $this->registry->markNotified($sid);
    }
}
