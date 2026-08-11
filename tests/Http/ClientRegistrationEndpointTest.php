<?php

declare(strict_types=1);

/**
 * RFC 7591 §3 (dynamic client registration)
 */

use Bambamboole\LaravelOidc\Server\Routing\Handler;
use Bambamboole\LaravelOidc\Server\Routing\HandlerRegistrar;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Passport;

/**
 * @param  array<string, mixed>  $overrides
 */
function enableDynamicClientRegistration(array $overrides = []): void
{
    config(['oidc.dcr' => [
        'enabled' => true,
        'allowed_redirect_schemes' => [],
        'allowed_redirect_domains' => ['*'],
        'default_scopes' => [],
        ...$overrides,
    ]]);

    app(HandlerRegistrar::class)->register();
    Route::getRoutes()->refreshNameLookups();
}

it('does not register the endpoint while the feature is disabled', function () {
    expect(Handler::ClientRegistration->config())->toBeFalse();

    $this->postJson('/oauth/register', ['redirect_uris' => ['https://rp.test/cb']])->assertNotFound();
});

it('registers a public client and returns the RFC 7591 response', function () {
    enableDynamicClientRegistration();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Claude',
        'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
    ])->assertCreated();

    $response->assertJson([
        'client_name' => 'Claude',
        'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
        'response_types' => ['code'],
        'token_endpoint_auth_method' => 'none',
        'client_secret_expires_at' => 0,
    ]);

    expect($response->json('client_id'))->toBeString()->not->toBeEmpty()
        ->and($response->json('client_id_issued_at'))->toBeInt()
        ->and($response->json('grant_types'))->toContain('authorization_code', 'refresh_token')
        ->and($response->json())->not->toHaveKey('client_secret');

    $client = Passport::client()->newQuery()->whereKey($response->json('client_id'))->firstOrFail();

    expect($client->confidential())->toBeFalse();
});

it('restricts the registered client to the configured default scopes', function () {
    enableDynamicClientRegistration(['default_scopes' => ['mcp:use', 'openid']]);

    $response = $this->postJson('/oauth/register', [
        'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
    ])->assertCreated()->assertJsonPath('scope', 'mcp:use openid');

    $client = Passport::client()->newQuery()->whereKey($response->json('client_id'))->firstOrFail();

    expect($client->getAttribute('scopes'))->toBe(['mcp:use', 'openid']);
});

it('falls back to the redirect host as client name', function () {
    enableDynamicClientRegistration();

    $this->postJson('/oauth/register', ['redirect_uris' => ['https://claude.ai/api/mcp/auth_callback']])
        ->assertCreated()
        ->assertJsonPath('client_name', 'claude.ai');
});

it('ignores unknown RFC 7591 metadata fields', function () {
    enableDynamicClientRegistration();

    $this->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://cursor.com/oauth/callback'],
        'application_type' => 'native',
        'software_id' => 'cursor',
        'token_endpoint_auth_method' => 'client_secret_basic',
    ])->assertCreated()->assertJsonPath('token_endpoint_auth_method', 'none');
});

it('rejects a missing or empty redirect uri list', function () {
    enableDynamicClientRegistration();

    $this->postJson('/oauth/register', ['client_name' => 'X'])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_client_metadata');

    $this->postJson('/oauth/register', ['redirect_uris' => []])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_client_metadata');
});

it('rejects malformed redirect uris', function (string $uri) {
    enableDynamicClientRegistration();

    $this->postJson('/oauth/register', ['redirect_uris' => [$uri]])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_redirect_uri');
})->with([
    'fragment' => 'https://rp.test/cb#fragment',
    'userinfo' => 'https://user:pass@rp.test/cb',
    'no host' => 'https:///cb',
    'control characters' => "https://rp.test/cb\x01",
    'relative' => '/callback',
]);

it('rejects custom schemes unless allow-listed', function () {
    enableDynamicClientRegistration();

    $this->postJson('/oauth/register', ['redirect_uris' => ['cursor://anysphere.cursor-retrieval/oauth/callback']])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_redirect_uri');

    enableDynamicClientRegistration(['allowed_redirect_schemes' => ['cursor']]);

    $this->postJson('/oauth/register', ['redirect_uris' => ['cursor://anysphere.cursor-retrieval/oauth/callback']])
        ->assertCreated();

    $this->postJson('/oauth/register', ['redirect_uris' => ['cursor:/callback']])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_redirect_uri');
});

it('enforces the redirect domain allowlist for http(s) uris', function () {
    enableDynamicClientRegistration(['allowed_redirect_domains' => ['claude.ai']]);

    $this->postJson('/oauth/register', ['redirect_uris' => ['https://claude.ai/api/mcp/auth_callback']])
        ->assertCreated();

    $this->postJson('/oauth/register', ['redirect_uris' => ['https://evil.test/cb']])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_redirect_uri');
});

it('throttles the registration endpoint', function () {
    enableDynamicClientRegistration();

    expect(Route::getRoutes()->getByName(Handler::ClientRegistration->value)->middleware())->toContain('throttle');
});
