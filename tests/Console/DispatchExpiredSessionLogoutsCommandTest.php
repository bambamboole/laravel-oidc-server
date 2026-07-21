<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Models\OidcSession;
use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Bambamboole\LaravelOidc\BackChannel\SendBackChannelLogout;
use Illuminate\Support\Facades\Bus;
use Laravel\Passport\ClientRepository;

it('dispatches logout for expired un-notified sessions exactly once', function () {
    Bus::fake();
    $sid = app(SessionRegistry::class)->start('5');
    OidcSession::query()->whereKey($sid)->update(['expires_at' => now()->subMinute()]);

    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('A', ['https://a.test/cb']);
    $client->forceFill(['backchannel_logout_uri' => 'https://a.test/bclo'])->save();
    app(SessionRegistry::class)->recordParticipant($sid, (string) $client->id);

    $this->artisan('oidc:dispatch-expired-session-logouts')->assertExitCode(0);
    $this->artisan('oidc:dispatch-expired-session-logouts')->assertExitCode(0); // idempotent

    Bus::assertDispatchedTimes(SendBackChannelLogout::class, 1);
    expect(OidcSession::query()->find($sid)->logout_notified_at)->not->toBeNull();
});
