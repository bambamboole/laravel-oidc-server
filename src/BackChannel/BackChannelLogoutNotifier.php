<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\BackChannel;

use Bambamboole\LaravelOidc\Server\Session\OidcSessionRepository;
use Laravel\Passport\Passport;

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
            $notifiable = Passport::client()->newQuery()
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
