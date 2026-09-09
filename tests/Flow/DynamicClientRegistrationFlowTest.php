<?php

declare(strict_types=1);

/**
 * RFC 7591 registration feeding the OAuth 2.1 §4.1 authorization code grant
 * with RFC 7636 PKCE (S256) — the discovery → register → authorize → token
 * chain MCP clients drive.
 */

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

it('lets a dynamically registered client complete the PKCE authorization code flow', function () {
    config(['oidc.dcr.enabled' => true, 'oidc.dcr.default_scopes' => []]);
    reloadOidcRoutes();

    $registration = $this->postJson('/realms/default/oauth/register', [
        'client_name' => 'MCP Client',
        'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
    ])->assertCreated();

    $client = Client::query()->whereKey($registration->json('client_id'))->firstOrFail();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    $result = $this->authorizeAndApprove($user, $client, 'openid', [
        'redirect_uri' => 'https://claude.ai/api/mcp/auth_callback',
    ]);

    $result->response->assertOk();

    expect($result->accessToken)->not->toBeNull();

    $this->withToken($result->accessToken)->getJson('/realms/default/oauth/userinfo')->assertOk();
});
