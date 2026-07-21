<?php
declare(strict_types=1);

/**
 * OpenID Connect Core 1.0 §5.3 (UserInfo endpoint)
 */

use Bambamboole\LaravelOidc\Claims\ClaimSet;
use Bambamboole\LaravelOidc\Contracts\ClaimsResolver;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Passport;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
});

it('returns an RFC 6750 error on an unauthenticated userinfo request', function () {
    $response = $this->getJson('/oauth/userinfo');
    $response->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token')
        ->assertHeader('WWW-Authenticate', 'Bearer realm="OIDC", error="invalid_token"');
});

it('returns insufficient_scope when the token lacks openid', function () {
    Passport::actingAs($this->user, ['email']);
    $this->getJson('/oauth/userinfo')
        ->assertForbidden()
        ->assertJsonPath('error', 'insufficient_scope')
        ->assertHeader('WWW-Authenticate', 'Bearer realm="OIDC", error="insufficient_scope"');
});

it('returns sub plus scope-filtered claims', function () {
    Passport::actingAs($this->user, ['openid', 'email']);

    $this->getJson('/oauth/userinfo')
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
        public function resolve(Authenticatable $user): ClaimSet
        {
            return new ClaimSet([
                'tenant' => ['tenant' => 'acme'],
            ]);
        }
    });

    Passport::actingAs($this->user, ['openid', 'tenant']);

    $this->getJson('/oauth/userinfo')
        ->assertOk()
        ->assertExactJson([
            'sub' => (string) $this->user->id,
            'tenant' => 'acme',
        ]);
});

it('includes profile claims when granted', function () {
    Passport::actingAs($this->user, ['openid', 'profile', 'email']);

    $response = $this->getJson('/oauth/userinfo')->assertOk();

    expect($response->json('name'))->toBe('M')
        ->and($response->json('sub'))->toBe((string) $this->user->id);
});

it('accepts POST as required by the spec', function () {
    Passport::actingAs($this->user, ['openid']);

    $this->postJson('/oauth/userinfo')->assertOk()->assertJson(['sub' => (string) $this->user->id]);
});
