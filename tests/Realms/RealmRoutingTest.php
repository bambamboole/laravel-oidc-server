<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Realms\RealmResolver;

beforeEach(function () {
    config(['oidc.issuer' => 'https://id.example.com']);
});

it('gives each realm its own issuer', function () {
    $acme = $this->getJson('/realms/acme/.well-known/openid-configuration')->assertOk();
    $globex = $this->getJson('/realms/globex/.well-known/openid-configuration')->assertOk();

    expect($acme->json('issuer'))->toBe('https://id.example.com/realms/acme')
        ->and($globex->json('issuer'))->toBe('https://id.example.com/realms/globex');
});

it('advertises realm-scoped endpoints without repeating the realm segment', function () {
    $document = $this->getJson('/realms/acme/.well-known/openid-configuration')->assertOk()->json();

    expect($document['authorization_endpoint'])->toBe('https://id.example.com/realms/acme/oauth/authorize')
        ->and($document['token_endpoint'])->toBe('https://id.example.com/realms/acme/oauth/token')
        ->and($document['jwks_uri'])->toBe('https://id.example.com/realms/acme/.well-known/jwks.json');
});

it('serves the RFC 8414 insertion form with the realm behind the well-known segment', function () {
    $inserted = $this->getJson('/.well-known/oauth-authorization-server/realms/acme')->assertOk()->json();
    $appended = $this->getJson('/realms/acme/.well-known/openid-configuration')->assertOk()->json();

    expect($inserted)->toBe($appended)
        ->and($inserted['issuer'])->toBe('https://id.example.com/realms/acme');
});

it('resolves the realm from the route for the request', function () {
    $this->get('/realms/globex/.well-known/jwks.json')->assertOk();

    $route = app('router')->getRoutes()->getByName('oidc.jwks');

    expect($route->uri())->toBe('realms/{realm}/.well-known/jwks.json');
});

it('falls back to the configured realm outside a matched route', function () {
    config(['oidc.realm' => 'fallback']);

    expect(app(RealmResolver::class)->current())->toBe('fallback')
        ->and(app(IssuerResolver::class)->url())->toBe('https://id.example.com/realms/fallback');
});

it('scopes the session cookie to the realm path', function () {
    $response = $this->get('/realms/acme/auth/login');

    $cookie = collect($response->headers->getCookies())
        ->first(fn ($cookie): bool => $cookie->getName() === config('session.cookie'));

    expect($cookie)->not->toBeNull()
        ->and($cookie->getPath())->toBe('/realms/acme');
});

it('rejects a realm segment that would collide with the well-known paths', function () {
    $this->getJson('/realms/a%2Fb/.well-known/openid-configuration')->assertNotFound();
});
