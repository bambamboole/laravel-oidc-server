<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\BackChannel\BackChannelLogoutNotifier;
use Bambamboole\LaravelOidc\Server\BackChannel\SendBackChannelLogout;
use Bambamboole\LaravelOidc\Server\Session\OidcSessionRepository;
use Illuminate\Support\Facades\Bus;
use Laravel\Passport\ClientRepository;

it('dispatches a job only for participants with a backchannel_logout_uri', function () {
    Bus::fake();
    $sid = app(OidcSessionRepository::class)->start('7');

    $withUri = app(ClientRepository::class)->createAuthorizationCodeGrantClient('A', ['https://a.test/cb']);
    $withUri->forceFill(['backchannel_logout_uri' => 'https://a.test/bclo'])->save();
    $withoutUri = app(ClientRepository::class)->createAuthorizationCodeGrantClient('B', ['https://b.test/cb']);

    app(OidcSessionRepository::class)->recordParticipant($sid, (string) $withUri->id);
    app(OidcSessionRepository::class)->recordParticipant($sid, (string) $withoutUri->id);

    app(BackChannelLogoutNotifier::class)->notify($sid);

    Bus::assertDispatchedTimes(SendBackChannelLogout::class, 1);
    Bus::assertDispatched(SendBackChannelLogout::class, fn (SendBackChannelLogout $j) => $j->clientId === (string) $withUri->id);
});
