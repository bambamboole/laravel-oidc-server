<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Bambamboole\LaravelOidc\BackChannel\SendBackChannelLogout;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\ClientRepository;

it('posts a logout_token to the client backchannel_logout_uri', function () {
    Http::fake();
    $sid = app(SessionRegistry::class)->start('9');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('A', ['https://a.test/cb']);
    $client->forceFill(['backchannel_logout_uri' => 'https://rp.test/bclo'])->save();

    SendBackChannelLogout::dispatchSync($sid, (string) $client->id);

    Http::assertSent(function (Request $request) {
        return $request->url() === 'https://rp.test/bclo'
            && is_string($request['logout_token'])
            && $request['logout_token'] !== '';
    });
});

it('does not post when the session is missing', function () {
    Http::fake();
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('A', ['https://a.test/cb']);
    $client->forceFill(['backchannel_logout_uri' => 'https://rp.test/bclo'])->save();

    SendBackChannelLogout::dispatchSync('nonexistent-sid', (string) $client->id);

    Http::assertNothingSent();
});

it('does not post when the client is missing', function () {
    Http::fake();
    $sid = app(SessionRegistry::class)->start('9');

    SendBackChannelLogout::dispatchSync($sid, 'nonexistent-client-id');

    Http::assertNothingSent();
});

it('does not post when the client has no backchannel_logout_uri', function () {
    Http::fake();
    $sid = app(SessionRegistry::class)->start('9');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('A', ['https://a.test/cb']);

    SendBackChannelLogout::dispatchSync($sid, (string) $client->id);

    Http::assertNothingSent();
});
