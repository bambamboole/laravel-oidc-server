<?php

declare(strict_types=1);

/**
 * OAuth 2.1 §4.2 (client credentials grant)
 */

use Bambamboole\LaravelOidc\Server\Auth\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Server\Auth\Pipeline\ClientCredentialsEvent;
use Bambamboole\LaravelOidc\Server\Facades\Oidc;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;

beforeEach(function () {
    $this->client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
});

it('issues a client_credentials token with its own configured lifetime', function () {
    config(['oidc.token_lifetimes.client_credentials' => 3600]);

    $response = $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'scope' => '',
    ])->assertOk();

    expect($response->json('expires_in'))->toBeLessThanOrEqual(3600)
        ->and($response->json('expires_in'))->toBeGreaterThan(3300);
});

it('runs the client-credentials trigger once and applies its access-token claims', function () {
    $triggerCount = 0;

    Oidc::clientCredentials(function (ClientCredentialsEvent $event, AccessTokenApi $api) use (&$triggerCount): void {
        $triggerCount++;

        expect($event->client->getIdentifier())->toBe((string) $this->client->id)
            ->and($event->scopes)->toBe([]);

        $api->setAccessTokenClaim('tenant', 'acme');
    });

    $response = $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'scope' => '',
    ])->assertOk();

    $accessToken = parseAccessToken((string) $response->json('access_token'));

    expect($accessToken->claims()->get('tenant'))->toBe('acme')
        ->and($triggerCount)->toBe(1);
});

it('binds the token to an allowlisted requested resource', function () {
    $this->client->forceFill(['allowed_exchange_audiences' => json_encode(['https://mail.test'])])->save();

    $response = $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'scope' => '',
        'resource' => 'https://mail.test',
    ])->assertOk();

    $accessToken = parseAccessToken((string) $response->json('access_token'));

    expect($accessToken->claims()->get('aud'))->toBe(['https://mail.test']);
});

it('defaults the audience to the client itself without a resource parameter', function () {
    $response = $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'scope' => '',
    ])->assertOk();

    $accessToken = parseAccessToken((string) $response->json('access_token'));

    expect($accessToken->claims()->get('aud'))->toBe([(string) $this->client->id]);
});

it('rejects a resource the client is not allowed to target', function () {
    $this->client->forceFill(['allowed_exchange_audiences' => json_encode(['https://mail.test'])])->save();

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'scope' => '',
        'resource' => 'https://somewhere-else.test',
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_target')
        ->assertJsonMissingPath('access_token');
});

it('rejects a resource that is not an absolute URI', function () {
    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'scope' => '',
        'resource' => 'not-a-uri',
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_target');
});

it('exposes the requested audiences to the client-credentials trigger', function () {
    $this->client->forceFill(['allowed_exchange_audiences' => json_encode(['https://mail.test'])])->save();
    $seen = null;

    Oidc::clientCredentials(function (ClientCredentialsEvent $event, AccessTokenApi $api) use (&$seen): void {
        $seen = $event->audiences;
    });

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'scope' => '',
        'resource' => 'https://mail.test',
    ])->assertOk();

    expect($seen)->toBe(['https://mail.test']);
});

it('denies client credentials before persisting an access token', function () {
    $persistedTokenCount = Passport::token()->newQuery()->count();

    Oidc::clientCredentials(function (ClientCredentialsEvent $event, AccessTokenApi $api): void {
        $api->deny('client_blocked');
    });

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'scope' => '',
    ])->assertStatus(401)
        ->assertJsonPath('error', 'access_denied')
        ->assertJsonMissingPath('access_token');

    expect(Passport::token()->newQuery()->count())->toBe($persistedTokenCount);
});
