<?php

declare(strict_types=1);

/**
 * OpenID Connect Back-Channel Logout 1.0 §2.5 (logout_token POSTed to the backchannel_logout_uri)
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Sessions\BackChannel\SendBackChannelLogout;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

beforeEach(fn () => Http::fake());

it('posts a logout_token to the client backchannel_logout_uri', function () {
    $sid = app(OidcSessionRepository::class)->start('9');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('A', ['https://a.test/cb']);
    $client->forceFill(['backchannel_logout_uri' => 'https://rp.test/bclo'])->save();

    SendBackChannelLogout::dispatchSync($sid, (string) $client->id);

    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://rp.test/bclo'
        && is_string($request['logout_token'])
        && $request['logout_token'] !== '');
});

it('sends nothing when the session, the client or its backchannel_logout_uri is missing', function (string $case) {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('A', ['https://a.test/cb']);
    $sid = app(OidcSessionRepository::class)->start('9');

    match ($case) {
        'missing session' => (function () use ($client): void {
            $client->forceFill(['backchannel_logout_uri' => 'https://rp.test/bclo'])->save();
            SendBackChannelLogout::dispatchSync('nonexistent-sid', (string) $client->id);
        })(),
        'missing client' => SendBackChannelLogout::dispatchSync($sid, 'nonexistent-client-id'),
        'no backchannel_logout_uri' => SendBackChannelLogout::dispatchSync($sid, (string) $client->id),
        default => throw new LogicException('Unknown case.'),
    };

    Http::assertNothingSent();
})->with(['missing session', 'missing client', 'no backchannel_logout_uri']);
