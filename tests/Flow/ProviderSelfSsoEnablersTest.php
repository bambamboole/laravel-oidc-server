<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    Passport::authorizationView(fn (array $parameters) => response()->json([
        'authToken' => $parameters['authToken'],
    ]));

    $this->user = User::create([
        'name' => 'M',
        'email' => 'm@example.com',
        'email_verified_at' => now(),
        'password' => 'x',
    ]);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Self RP', ['https://rp.test/callback']);
});

/**
 * @param  array<string, string>  $overrides
 * @return array<string, string>
 */
function selfSsoAuthorizationQuery(string|int $clientId, array $overrides = []): array
{
    $verifier = str_repeat('v', 64);
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

    return array_merge([
        'client_id' => (string) $clientId,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid email',
        'state' => 'st4te',
        'nonce' => 'n0nce',
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
    ], $overrides);
}

it('redirects unauthenticated authorization requests to the configured identity login route', function () {
    config(['oidc.login_route' => 'identity.login']);

    $this->get('/oauth/authorize?'.http_build_query(selfSsoAuthorizationQuery($this->client->id)))
        ->assertRedirect('/auth/login');
});

it('accepts a literal path as the authorization login destination', function () {
    config(['oidc.login_route' => '/custom/identity-login']);

    $this->get('/oauth/authorize?'.http_build_query(selfSsoAuthorizationQuery($this->client->id)))
        ->assertRedirect('/custom/identity-login');
});

it('returns credential login to the pending authorization request without creating a web session', function () {
    config(['oidc.login_route' => 'identity.login']);
    $this->user->forceFill(['password' => Hash::make('password')])->save();

    $this->get('/oauth/authorize?'.http_build_query(selfSsoAuthorizationQuery($this->client->id)))
        ->assertRedirect('/auth/login');

    $response = $this->post(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'password',
    ])->assertRedirect();

    expect($response->headers->get('Location'))->toContain('/oauth/authorize?')
        ->and(auth('identity')->check())->toBeTrue()
        ->and(auth('web')->guest())->toBeTrue();
});

it('auto-approves trusted clients without rendering consent', function () {
    config(['oidc.trusted_clients' => [$this->client->id]]);

    $response = $this->actingAs($this->user, (string) config('oidc.auth.guard'))
        ->withSession(['oidc.auth_time' => time()])
        ->get('/oauth/authorize?'.http_build_query(selfSsoAuthorizationQuery($this->client->id)));

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toStartWith('https://rp.test/callback?')
        ->toContain('code=');
});

it('does not bypass consent for an untrusted first-party client', function () {
    config([
        'oidc.first_party' => [
            'client_id' => (string) $this->client->id,
            'trusted' => false,
        ],
        'oidc.trusted_clients' => [(string) $this->client->id],
    ]);

    $this->actingAs($this->user, (string) config('oidc.auth.guard'))
        ->withSession(['oidc.auth_time' => time()])
        ->get('/oauth/authorize?'.http_build_query(selfSsoAuthorizationQuery($this->client->id)))
        ->assertOk()
        ->assertJsonStructure(['authToken']);
});

it('auto-approves a trusted first-party client without duplicating its id', function () {
    config([
        'oidc.first_party' => [
            'client_id' => (string) $this->client->id,
            'trusted' => true,
        ],
        'oidc.trusted_clients' => [],
    ]);

    $response = $this->actingAs($this->user, (string) config('oidc.auth.guard'))
        ->withSession(['oidc.auth_time' => time()])
        ->get('/oauth/authorize?'.http_build_query(selfSsoAuthorizationQuery($this->client->id)));

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toStartWith('https://rp.test/callback?')
        ->toContain('code=');
});

it('does not show forced consent for trusted clients', function () {
    config(['oidc.trusted_clients' => [$this->client->id]]);

    $response = $this->actingAs($this->user, (string) config('oidc.auth.guard'))
        ->withSession(['oidc.auth_time' => time()])
        ->get('/oauth/authorize?'.http_build_query(selfSsoAuthorizationQuery($this->client->id, [
            'prompt' => 'consent',
        ])));

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toStartWith('https://rp.test/callback?')
        ->toContain('code=');
});

it('satisfies prompt none for an authenticated trusted client', function () {
    config(['oidc.trusted_clients' => [$this->client->id]]);

    $response = $this->actingAs($this->user, (string) config('oidc.auth.guard'))
        ->withSession(['oidc.auth_time' => time()])
        ->get('/oauth/authorize?'.http_build_query(selfSsoAuthorizationQuery($this->client->id, [
            'prompt' => 'none',
        ])));

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toStartWith('https://rp.test/callback?')
        ->toContain('code=');
});
