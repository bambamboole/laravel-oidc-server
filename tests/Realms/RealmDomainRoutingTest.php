<?php

declare(strict_types=1);

/**
 * OpenID Connect Discovery 1.0 §4 (issuer + /.well-known/openid-configuration);
 * RFC 8414 §3.1 (well-known segment ahead of the issuer path)
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Tests\Realms\RecordResolvedRealm;
use Bambamboole\LaravelOidc\Server\Tests\Realms\RoutesRealmsByDomain;

uses(RoutesRealmsByDomain::class);

beforeEach(function (): void {
    config(['oidc.routes.domains' => [
        'localhost' => 'default',
        'acme.id.test' => 'acme',
        'globex.id.test' => 'globex',
    ]]);
});

it('serves every endpoint at its canonical path, with the well-known segment in front', function (): void {
    $this->getJson('https://acme.id.test/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://acme.id.test')
        ->assertJsonPath('jwks_uri', 'https://acme.id.test/.well-known/jwks.json')
        ->assertJsonPath('token_endpoint', 'https://acme.id.test/oauth/token')
        ->assertJsonPath('authorization_endpoint', 'https://acme.id.test/oauth/authorize');
});

it('gives each host its own issuer', function (): void {
    $this->getJson('https://acme.id.test/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://acme.id.test');

    $this->getJson('https://globex.id.test/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://globex.id.test');
});

// RFC 8414 §3.1 — with no path in the issuer, the well-known segment is all there is
it('serves the authorization server metadata at the bare well-known path', function (): void {
    $this->getJson('https://acme.id.test/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://acme.id.test');
});

it('serves the realm key set from the realm host', function (): void {
    $this->get('https://acme.id.test/.well-known/openid-configuration');
    generateRealmSigningKey();

    $this->getJson('https://acme.id.test/.well-known/jwks.json')
        ->assertOk()
        ->assertJsonCount(1, 'keys');
});

it('resolves the realm from the host', function (): void {
    $this->get('https://acme.id.test/.well-known/openid-configuration');

    expect(app(RealmResolver::class)->current()->id())->toBe('acme')
        ->and(app(IssuerResolver::class)->url())->toBe('https://acme.id.test');
});

it('answers 404 for a host no realm is served from', function (): void {
    $this->getJson('https://unknown.id.test/.well-known/openid-configuration')->assertNotFound();
});

it('scopes rows to the realm the host names', function (): void {
    $this->get('https://acme.id.test/.well-known/openid-configuration');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    expect($client->realm_id)->toBe('acme');

    $this->get('https://globex.id.test/.well-known/openid-configuration');

    expect(app(ClientRepository::class)->find($client->client_id))->toBeNull();
});

// A worker has no host to resolve from, so the realm has to come from the job.
it('resolves the realm a job was dispatched from when there is no host', function (): void {
    config(['queue.default' => 'database', 'oidc.issuer' => 'https://id.example.com']);
    RecordResolvedRealm::forget();

    $this->get('https://acme.id.test/.well-known/openid-configuration')->assertOk();
    RecordResolvedRealm::dispatch();

    forgetRequest();
    workQueue();

    expect(RecordResolvedRealm::$seen['realm'])->toBe('acme')
        ->and(RecordResolvedRealm::$seen['issuer'])->toBe('https://acme.id.test');
});
