<?php
declare(strict_types=1);

/**
 * OpenID Connect Core 1.0 §5.3 (UserInfo endpoint)
 */

use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimSet;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsRequest;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsResolver;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
});

it('returns an RFC 6750 error on an unauthenticated userinfo request', function () {
    $response = $this->getJson('/realms/default/oauth/userinfo');
    $response->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token')
        ->assertHeader('WWW-Authenticate', 'Bearer realm="OIDC", error="invalid_token"');
});

it('returns insufficient_scope when the token lacks openid', function () {
    $this->actingAsOidcUser($this->user, ['email'], 'oidc');
    $this->getJson('/realms/default/oauth/userinfo')
        ->assertForbidden()
        ->assertJsonPath('error', 'insufficient_scope')
        ->assertHeader('WWW-Authenticate', 'Bearer realm="OIDC", error="insufficient_scope"');
});

it('returns sub plus scope-filtered claims', function () {
    $this->actingAsOidcUser($this->user, ['openid', 'email'], 'oidc');

    $this->getJson('/realms/default/oauth/userinfo')
        ->assertOk()
        ->assertExactJson([
            'sub' => (string) $this->user->id,
            'email' => 'm@example.com',
            'email_verified' => true,
        ]);
});

it('includes scoped claims from a custom claims resolver', function () {
    app()->instance(ClaimsResolver::class, new class implements ClaimsResolver
    {
        public function resolve(ClaimsRequest $request): array
        {
            return (new ClaimSet([
                'tenant' => ['tenant' => 'acme'],
            ]))->forScopes($request->scopes);
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

it('includes profile claims when granted', function () {
    $this->actingAsOidcUser($this->user, ['openid', 'profile', 'email'], 'oidc');

    $response = $this->getJson('/realms/default/oauth/userinfo')->assertOk();

    expect($response->json('name'))->toBe('M')
        ->and($response->json('sub'))->toBe((string) $this->user->id);
});

it('accepts POST as required by the spec', function () {
    $this->actingAsOidcUser($this->user, ['openid'], 'oidc');

    $this->postJson('/realms/default/oauth/userinfo')->assertOk()->assertJson(['sub' => (string) $this->user->id]);
});
