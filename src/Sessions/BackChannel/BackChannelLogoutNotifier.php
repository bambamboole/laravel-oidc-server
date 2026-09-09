<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions\BackChannel;

use Bambamboole\LaravelOidc\Server\Clients\Client;
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

        $clientIds = $this->registry->participantClientIds($sid);

        if ($clientIds !== []) {
            $notifiable = Client::query()
                ->whereIn('id', $clientIds)
                ->whereNotNull('backchannel_logout_uri')
                ->pluck('id');

            foreach ($notifiable as $clientId) {
                SendBackChannelLogout::dispatch($sid, (string) $clientId);
            }
        }

        $this->registry->markNotified($sid);
    }
}
