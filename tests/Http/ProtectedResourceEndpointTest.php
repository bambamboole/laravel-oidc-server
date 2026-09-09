<?php

declare(strict_types=1);

/**
 * RFC 9728 §3 (protected resource metadata)
 */
it('serves metadata for a configured protected resource', function () {
    config([
        'app.url' => 'https://op.test',
        'oidc.issuer' => null,
        'oidc.protected_resources' => ['mcp' => ['scopes' => ['mcp:use']]],
    ]);

    $this->getJson('/.well-known/oauth-protected-resource/realms/default/mcp')
        ->assertOk()
        ->assertHeader('Cache-Control', 'max-age=3600, public')
        ->assertExactJson([
            'resource' => 'https://op.test/realms/default/mcp',
            'authorization_servers' => ['https://op.test/realms/default'],
            'scopes_supported' => ['mcp:use'],
            'bearer_methods_supported' => ['header'],
        ]);
});

it('builds the resource identifier from the configured issuer', function () {
    config([
        'oidc.issuer' => 'https://id.example.com/',
        'oidc.protected_resources' => ['mcp' => ['scopes' => []]],
    ]);

    $this->getJson('/.well-known/oauth-protected-resource/realms/default/mcp')
        ->assertOk()
        ->assertJsonPath('resource', 'https://id.example.com/realms/default/mcp')
        ->assertJsonPath('authorization_servers.0', 'https://id.example.com/realms/default');
});

it('serves the issuer root as resource when configured under an empty path', function () {
    config([
        'oidc.issuer' => 'https://op.test',
        'oidc.protected_resources' => ['' => ['scopes' => ['api']]],
    ]);

    $this->getJson('/.well-known/oauth-protected-resource/realms/default')
        ->assertOk()
        ->assertJsonPath('resource', 'https://op.test/realms/default');
});

it('404s for resources that are not configured', function () {
    config(['oidc.protected_resources' => ['mcp' => ['scopes' => []]]]);

    $this->getJson('/.well-known/oauth-protected-resource/realms/default/unknown')->assertNotFound();
    $this->getJson('/.well-known/oauth-protected-resource/realms/default')->assertNotFound();
});
