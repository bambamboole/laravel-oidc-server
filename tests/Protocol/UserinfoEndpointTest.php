<?php

declare(strict_types=1);

/**
 * OpenID Connect Core 1.0 §5.3 (UserInfo endpoint), §5.3.2 (sub); RFC 6750 §3.1 (bearer challenges)
 */

use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimSet;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsRequest;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsResolver;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

const USERINFO_RESOURCE_METADATA = 'resource_metadata="http://localhost/.well-known/oauth-protected-resource/realms/default"';

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
});

it('challenges a request without a bearer token and names no error', function () {
    $this->getJson('/realms/default/oauth/userinfo')
        ->assertUnauthorized()
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", '.USERINFO_RESOURCE_METADATA)
        ->assertNoContent(401);
});

it('returns invalid_token for a bearer token the guard rejects', function () {
    $this->getJson('/realms/default/oauth/userinfo', ['Authorization' => 'Bearer garbage'])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token')
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", error="invalid_token", '.USERINFO_RESOURCE_METADATA);
});

it('returns insufficient_scope when the token lacks openid', function () {
    $this->actingAsOidcUser($this->user, ['email'], 'oidc');

    $this->getJson('/realms/default/oauth/userinfo')
        ->assertForbidden()
        ->assertJsonPath('error', 'insufficient_scope')
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", error="insufficient_scope", '.USERINFO_RESOURCE_METADATA);
});

it('returns sub plus the claims the granted scopes cover on GET and POST', function () {
    $this->actingAsOidcUser($this->user, ['openid', 'profile', 'email'], 'oidc');

    $response = $this->getJson('/realms/default/oauth/userinfo')->assertOk();

    expect($response->json('sub'))->toBe((string) $this->user->id)
        ->and($response->json('name'))->toBe('M')
        ->and($response->json('email'))->toBe('m@example.com')
        ->and($response->json('email_verified'))->toBeTrue();

    $this->postJson('/realms/default/oauth/userinfo')->assertOk()->assertJson(['sub' => (string) $this->user->id]);
});

it('includes scoped claims from a custom claims resolver and drops the protocol claims it emits', function () {
    app()->instance(ClaimsResolver::class, new class implements ClaimsResolver
    {
        public function resolve(ClaimsRequest $request): array
        {
            return [
                'sub' => 'someone-else',
                'iss' => 'https://evil.test',
                'aud' => ['other'],
                ...(new ClaimSet(['tenant' => ['tenant' => 'acme']]))->forScopes($request->scopes),
            ];
        }
    });

    $this->actingAsOidcUser($this->user, ['openid', 'tenant'], 'oidc');

    $this->getJson('/realms/default/oauth/userinfo')
        ->assertOk()
        ->assertExactJson([
            'sub' => (string) $this->user->id,
            'tenant' => 'acme',
        ]);
});
