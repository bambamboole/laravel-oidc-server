<?php

declare(strict_types=1);

/**
 * OAuth 2.1 §4.2 (client credentials grant)
 */

use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Auth\Pipeline\ClientCredentialsEvent;
use Bambamboole\LaravelOidc\Facades\Oidc;
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
