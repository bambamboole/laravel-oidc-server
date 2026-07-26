<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Auth\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\BackChannel\SendBackChannelLogout;
use Bambamboole\LaravelOidc\Server\Session\OidcSessionRepository;
use Illuminate\Support\Facades\Bus;
use Laravel\Passport\ClientRepository;

it('dispatches logout for expired un-notified sessions exactly once', function () {
    Bus::fake();
    $sid = app(OidcSessionRepository::class)->start('5');
    OidcSession::query()->whereKey($sid)->update(['expires_at' => now()->subMinute()]);

    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('A', ['https://a.test/cb']);
    $client->forceFill(['backchannel_logout_uri' => 'https://a.test/bclo'])->save();
    app(OidcSessionRepository::class)->recordParticipant($sid, (string) $client->id);

    $this->artisan('oidc:dispatch-expired-session-logouts')->assertExitCode(0);
    $this->artisan('oidc:dispatch-expired-session-logouts')->assertExitCode(0); // idempotent

    Bus::assertDispatchedTimes(SendBackChannelLogout::class, 1);
    expect(OidcSession::query()->find($sid)->logout_notified_at)->not->toBeNull();
});
