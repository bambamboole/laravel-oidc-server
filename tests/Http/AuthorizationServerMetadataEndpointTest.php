<?php

declare(strict_types=1);

/**
 * RFC 8414 §3 (authorization server metadata)
 */

use Bambamboole\LaravelOidc\Server\Routing\HandlerRegistrar;
use Illuminate\Support\Facades\Route;

it('serves the authorization server metadata document at the well-known path', function () {
    config(['app.url' => 'https://op.test', 'oidc.issuer' => null]);

    $response = $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertHeader('Cache-Control', 'max-age=3600, public');

    $response->assertJson([
        'issuer' => 'https://op.test',
        'response_types_supported' => ['code'],
        'code_challenge_methods_supported' => ['S256'],
        'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
    ]);

    expect($response->json('authorization_endpoint'))->toContain('/oauth/authorize')
        ->and($response->json('token_endpoint'))->toContain('/oauth/token')
        ->and($response->json('jwks_uri'))->toContain('/.well-known/jwks.json');
});

it('serves the identical document as the openid configuration', function () {
    $oauth = $this->getJson('/.well-known/oauth-authorization-server')->assertOk()->json();
    $oidc = $this->getJson('/.well-known/openid-configuration')->assertOk()->json();

    expect($oauth)->toBe($oidc);
});

it('serves the document under the RFC 8414 path-insertion form', function () {
    config(['oidc.issuer' => 'https://id.example.com']);

    $this->getJson('/.well-known/oauth-authorization-server/mcp')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://id.example.com');
});

it('omits the registration endpoint while dynamic client registration is disabled', function () {
    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonMissingPath('registration_endpoint');
});

it('advertises the registration endpoint once dynamic client registration is enabled', function () {
    config(['oidc.dcr.enabled' => true]);
    app(HandlerRegistrar::class)->register();
    Route::getRoutes()->refreshNameLookups();

    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('registration_endpoint', fn (string $url) => str_contains($url, '/oauth/register'));

    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('registration_endpoint', fn (string $url) => str_contains($url, '/oauth/register'));
});
