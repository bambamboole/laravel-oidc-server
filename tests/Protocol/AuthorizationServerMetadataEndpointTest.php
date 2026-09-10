<?php

declare(strict_types=1);

/**
 * RFC 8414 §3 (authorization server metadata well-known path, path-insertion form)
 */
it('serves the same document as the openid configuration under both well-known forms', function (): void {
    config(['oidc.issuer' => 'https://id.example.com']);

    $oidc = $this->getJson('/realms/default/.well-known/openid-configuration')->assertOk()->json();

    $this->getJson('/.well-known/oauth-authorization-server/realms/default')
        ->assertOk()
        ->assertHeader('Cache-Control', 'max-age=3600, public')
        ->assertExactJson($oidc);

    $this->getJson('/.well-known/oauth-authorization-server/realms/default/mcp')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://id.example.com/realms/default');
});

it('advertises the registration endpoint once dynamic client registration is enabled', function (): void {
    $this->getJson('/.well-known/oauth-authorization-server/realms/default')
        ->assertOk()
        ->assertJsonMissingPath('registration_endpoint');

    config(['oidc.clients.registration.enabled' => true]);
    reloadOidcRoutes();

    $this->getJson('/.well-known/oauth-authorization-server/realms/default')
        ->assertOk()
        ->assertJsonPath('registration_endpoint', fn (string $url): bool => str_contains($url, '/realms/default/oauth/register'));
});
