<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\Actions\RegisterClient;
use Bambamboole\LaravelOidc\Server\Clients\ClientRegistrationException;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;

it('registers a public authorization-code client from RFC 7591 metadata', function () {
    $audit = fakeAudit();
    config(['oidc.clients.registration.default_scopes' => ['openid']]);

    $client = app(RegisterClient::class)([
        'client_name' => '  Claude ',
        'redirect_uris' => ['https://claude.ai/cb', 'https://claude.ai/cb'],
        'software_id' => 'ignored',
    ]);

    expect($client->name)->toBe('Claude')
        ->and($client->redirect_uris)->toBe(['https://claude.ai/cb'])
        ->and($client->confidential())->toBeFalse()
        ->and($client->scopes)->toBe(['openid']);
    $audit->assertRecorded(AuditEventType::ClientRegistered);
});

it('derives the client name from the first redirect host when none is given', function () {
    $client = app(RegisterClient::class)(['redirect_uris' => ['https://rp.test/cb']]);

    expect($client->name)->toBe('rp.test');
});

it('rejects metadata without redirect uris', function () {
    app(RegisterClient::class)([]);
})->throws(ClientRegistrationException::class, 'At least one redirect URI is required.');

it('rejects redirect uris outside the allowed domains and schemes', function (array $uris, string $message) {
    config(['oidc.clients.registration.allowed_redirect_domains' => ['rp.test'], 'oidc.clients.registration.allowed_redirect_schemes' => ['myapp']]);

    try {
        app(RegisterClient::class)(['redirect_uris' => $uris]);
    } catch (ClientRegistrationException $exception) {
        expect($exception->error)->toBe('invalid_redirect_uri')
            ->and($exception->getMessage())->toContain($message);

        return;
    }

    $this->fail('Expected the registration to be rejected.');
})->with([
    'foreign host' => [['https://evil.test/cb'], 'host [evil.test] is not allowed'],
    'unknown scheme' => [['other://rp.test/cb'], 'scheme [other] is not allowed'],
    'fragment' => [['https://rp.test/cb#x'], 'without user information or a fragment'],
    'empty string' => [[''], 'non-empty strings'],
]);

it('accepts a custom scheme that is explicitly allowed', function () {
    config(['oidc.clients.registration.allowed_redirect_schemes' => ['myapp']]);

    expect(app(RegisterClient::class)(['redirect_uris' => ['myapp://rp.test/cb']])->redirect_uris)->toBe(['myapp://rp.test/cb']);
});
