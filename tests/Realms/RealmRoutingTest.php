<?php

declare(strict_types=1);

/**
 * OpenID Connect Discovery 1.0 §3 (one issuer per realm)
 */

use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;

beforeEach(function (): void {
    config(['oidc.issuer' => 'https://id.example.com']);
});

it('gives each realm its own issuer and realm-scoped endpoints', function (): void {
    $acme = $this->getJson('/realms/acme/.well-known/openid-configuration')->assertOk()->json();
    $globex = $this->getJson('/realms/globex/.well-known/openid-configuration')->assertOk()->json();

    expect($acme['issuer'])->toBe('https://id.example.com/realms/acme')
        ->and($globex['issuer'])->toBe('https://id.example.com/realms/globex')
        ->and($acme['authorization_endpoint'])->toBe('https://id.example.com/realms/acme/oauth/authorize')
        ->and($acme['token_endpoint'])->toBe('https://id.example.com/realms/acme/oauth/token')
        ->and($acme['jwks_uri'])->toBe('https://id.example.com/realms/acme/.well-known/jwks.json');
});

it('falls back to the configured realm outside a matched route', function (): void {
    config(['oidc.realm' => 'fallback']);

    expect(app(RealmResolver::class)->current()->id())->toBe('fallback')
        ->and(app(IssuerResolver::class)->url())->toBe('https://id.example.com/realms/fallback');
});

it('scopes the session cookie to the realm path', function (): void {
    $response = $this->get('/realms/acme/auth/login');

    $cookie = collect($response->headers->getCookies())
        ->first(fn ($cookie): bool => $cookie->getName() === config('session.cookie'));

    expect($cookie)->not->toBeNull()
        ->and($cookie->getPath())->toBe('/realms/acme');
});

it('rejects a realm segment that would collide with the well-known paths', function (): void {
    $this->getJson('/realms/a%2Fb/.well-known/openid-configuration')->assertNotFound();
});
