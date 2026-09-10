<?php

declare(strict_types=1);

/**
 * RFC 7591 §3 (dynamic client registration)
 */

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;

/**
 * @param  array<string, mixed>  $overrides
 */
function enableDynamicClientRegistration(array $overrides = []): void
{
    config(['oidc.clients.registration' => [
        'enabled' => true,
        'allowed_redirect_schemes' => [],
        'allowed_redirect_domains' => ['*'],
        'default_scopes' => [],
        ...$overrides,
    ]]);

    reloadOidcRoutes();
}

it('answers 404 while dynamic registration is disabled for the realm', function () {
    $this->postJson('/realms/default/oauth/register', ['redirect_uris' => ['https://rp.test/cb']])->assertNotFound();
});

it('registers a public client and returns the RFC 7591 response', function () {
    enableDynamicClientRegistration();

    $response = $this->postJson('/realms/default/oauth/register', [
        'client_name' => 'Claude',
        'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
    ])->assertCreated();

    $response->assertJson([
        'client_name' => 'Claude',
        'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
        'post_logout_redirect_uris' => [],
        'response_types' => ['code'],
        'token_endpoint_auth_method' => 'none',
    ]);

    // RFC 7591 §3.2.1: client_secret_expires_at accompanies an issued secret only
    expect($response->json('client_id'))->toBeString()->not->toBeEmpty()
        ->and($response->json('client_id_issued_at'))->toBeInt()
        ->and($response->json('grant_types'))->toBe(['authorization_code', 'refresh_token'])
        ->and($response->json())->not->toHaveKey('client_secret')
        ->and($response->json())->not->toHaveKey('client_secret_expires_at')
        ->and($response->json())->not->toHaveKey('backchannel_logout_uri');

    $client = Client::query()->whereKey($response->json('client_id'))->firstOrFail();

    expect($client->confidential())->toBeFalse();
});

it('restricts the registered client to the configured default scopes', function () {
    enableDynamicClientRegistration(['default_scopes' => ['mcp:use', 'openid']]);

    $response = $this->postJson('/realms/default/oauth/register', [
        'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
    ])->assertCreated()->assertJsonPath('scope', 'mcp:use openid');

    $client = Client::query()->whereKey($response->json('client_id'))->firstOrFail();

    expect($client->getAttribute('scopes'))->toBe(['mcp:use', 'openid']);
});

it('falls back to the redirect host as client name', function () {
    enableDynamicClientRegistration();

    $this->postJson('/realms/default/oauth/register', ['redirect_uris' => ['https://claude.ai/api/mcp/auth_callback']])
        ->assertCreated()
        ->assertJsonPath('client_name', 'claude.ai');
});

it('ignores unknown RFC 7591 metadata fields', function () {
    enableDynamicClientRegistration();

    $this->postJson('/realms/default/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://cursor.com/oauth/callback'],
        'application_type' => 'native',
        'software_id' => 'cursor',
    ])->assertCreated()->assertJsonPath('token_endpoint_auth_method', 'none');
});

// RFC 7591 §2, §3.2.1 — a secret-based auth method registers a confidential client; the secret is returned once
it('issues a secret to a client registering a secret-based token_endpoint_auth_method', function (string $method) {
    enableDynamicClientRegistration();

    $response = $this->postJson('/realms/default/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://cursor.com/oauth/callback'],
        'token_endpoint_auth_method' => $method,
    ])->assertCreated()
        ->assertJsonPath('token_endpoint_auth_method', $method)
        ->assertJsonPath('client_secret_expires_at', 0);

    $client = Client::query()->whereKey($response->json('client_id'))->firstOrFail();

    expect($response->json('client_secret'))->toBeString()->not->toBeEmpty()
        ->and($client->confidential())->toBeTrue()
        ->and($client->token_endpoint_auth_method->value)->toBe($method)
        ->and(Hash::check($response->json('client_secret'), $client->getAttributes()['secret']))->toBeTrue();
})->with(['client_secret_basic', 'client_secret_post']);

it('rejects an unsupported token_endpoint_auth_method', function () {
    enableDynamicClientRegistration();

    $this->postJson('/realms/default/oauth/register', [
        'redirect_uris' => ['https://rp.test/cb'],
        'token_endpoint_auth_method' => 'private_key_jwt',
    ])->assertBadRequest()->assertJsonPath('error', 'invalid_client_metadata');
});

// RFC 7591 §2 — grant_types ⊆ {authorization_code, refresh_token}, response_types == [code]
it('rejects grant_types and response_types this endpoint does not provision', function (array $metadata) {
    enableDynamicClientRegistration();

    $this->postJson('/realms/default/oauth/register', ['redirect_uris' => ['https://rp.test/cb'], ...$metadata])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_client_metadata');
})->with([
    'foreign grant' => [['grant_types' => ['authorization_code', 'implicit']]],
    'empty grants' => [['grant_types' => []]],
    'refresh only' => [['grant_types' => ['refresh_token']]],
    'grants not a list' => [['grant_types' => 'authorization_code']],
    'foreign response type' => [['response_types' => ['token']]],
    'empty response types' => [['response_types' => []]],
]);

it('registers the grant types a client asks for', function () {
    enableDynamicClientRegistration();

    $response = $this->postJson('/realms/default/oauth/register', [
        'redirect_uris' => ['https://rp.test/cb'],
        'grant_types' => ['authorization_code'],
        'response_types' => ['code'],
    ])->assertCreated()->assertJsonPath('grant_types', ['authorization_code']);

    expect(Client::query()->whereKey($response->json('client_id'))->firstOrFail()->grant_types)->toBe(['authorization_code']);
});

// OIDC RP-Initiated Logout §3, Back-Channel Logout §2.2 — logout metadata is stored and echoed
it('persists and echoes the logout metadata', function () {
    enableDynamicClientRegistration();

    $response = $this->postJson('/realms/default/oauth/register', [
        'redirect_uris' => ['https://rp.test/cb'],
        'post_logout_redirect_uris' => ['https://rp.test/logged-out', 'https://rp.test/logged-out'],
        'backchannel_logout_uri' => 'https://rp.test/backchannel?tenant=1',
        'backchannel_logout_session_required' => true,
    ])->assertCreated()->assertJson([
        'post_logout_redirect_uris' => ['https://rp.test/logged-out'],
        'backchannel_logout_uri' => 'https://rp.test/backchannel?tenant=1',
        'backchannel_logout_session_required' => true,
    ]);

    $client = Client::query()->whereKey($response->json('client_id'))->firstOrFail();

    expect($client->post_logout_redirect_uris)->toBe(['https://rp.test/logged-out'])
        ->and($client->backchannel_logout_uri)->toBe('https://rp.test/backchannel?tenant=1')
        ->and($client->backchannel_logout_session_required)->toBeTrue();
});

it('rejects a backchannel_logout_uri that is not an absolute https url', function (string $uri) {
    enableDynamicClientRegistration();

    $this->postJson('/realms/default/oauth/register', [
        'redirect_uris' => ['https://rp.test/cb'],
        'backchannel_logout_uri' => $uri,
    ])->assertBadRequest()->assertJsonPath('error', 'invalid_client_metadata');
})->with([
    'http' => 'http://rp.test/backchannel',
    'fragment' => 'https://rp.test/backchannel#x',
    'relative' => '/backchannel',
]);

it('validates post_logout_redirect_uris like redirect uris', function () {
    enableDynamicClientRegistration(['allowed_redirect_domains' => ['rp.test']]);

    $this->postJson('/realms/default/oauth/register', [
        'redirect_uris' => ['https://rp.test/cb'],
        'post_logout_redirect_uris' => ['https://evil.test/out'],
    ])->assertBadRequest()->assertJsonPath('error', 'invalid_client_metadata');

    $this->postJson('/realms/default/oauth/register', [
        'redirect_uris' => ['https://rp.test/cb'],
        'post_logout_redirect_uris' => 'https://rp.test/out',
    ])->assertBadRequest()->assertJsonPath('error', 'invalid_client_metadata');
});

it('rejects a missing or empty redirect uri list', function () {
    enableDynamicClientRegistration();

    $this->postJson('/realms/default/oauth/register', ['client_name' => 'X'])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_client_metadata');

    $this->postJson('/realms/default/oauth/register', ['redirect_uris' => []])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_client_metadata');
});

it('rejects malformed redirect uris', function (string $uri) {
    enableDynamicClientRegistration();

    $this->postJson('/realms/default/oauth/register', ['redirect_uris' => [$uri]])
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

    $this->postJson('/realms/default/oauth/register', ['redirect_uris' => ['cursor://anysphere.cursor-retrieval/oauth/callback']])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_redirect_uri');

    enableDynamicClientRegistration(['allowed_redirect_schemes' => ['cursor']]);

    $this->postJson('/realms/default/oauth/register', ['redirect_uris' => ['cursor://anysphere.cursor-retrieval/oauth/callback']])
        ->assertCreated();

    $this->postJson('/realms/default/oauth/register', ['redirect_uris' => ['cursor:/callback']])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_redirect_uri');
});

it('enforces the redirect domain allowlist for http(s) uris', function () {
    enableDynamicClientRegistration(['allowed_redirect_domains' => ['claude.ai']]);

    $this->postJson('/realms/default/oauth/register', ['redirect_uris' => ['https://claude.ai/api/mcp/auth_callback']])
        ->assertCreated();

    $this->postJson('/realms/default/oauth/register', ['redirect_uris' => ['https://evil.test/cb']])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_redirect_uri');
});

it('throttles the registration endpoint', function () {
    enableDynamicClientRegistration();

    expect(Route::getRoutes()->getByName('oidc.register')->middleware())->toContain('throttle');
});
