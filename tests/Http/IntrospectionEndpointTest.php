<?php

declare(strict_types=1);

/**
 * RFC 7662 (OAuth 2.0 Token Introspection)
 */

use Laravel\Passport\ClientRepository;
use Laravel\Passport\Token;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->secret = $this->client->plainSecret;
});

/**
 * @return array{0: string, 1: Token}
 */
function issueAccessTokenViaPersonalClient(mixed $test): array
{
    app(ClientRepository::class)->createPersonalAccessGrantClient('PAT', 'users');
    $result = $test->user->createToken('t', ['openid', 'email']);

    $token = $result->getToken();

    if (! $token instanceof Token) {
        throw new RuntimeException('Expected the personal access token to be persisted.');
    }

    return [$result->accessToken, $token];
}

it('rejects requests without client authentication', function () {
    $this->postJson('/oauth/introspect', ['token' => 'x'])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_client')
        ->assertHeader('WWW-Authenticate', 'Basic realm="OIDC"');
});

it('omits sub and exp when the token has no user or expiry', function () {
    [$jwt, $token] = issueAccessTokenViaPersonalClient($this);
    $token->forceFill(['client_id' => $this->client->id, 'user_id' => null, 'expires_at' => null])->save();

    $response = $this->postJson('/oauth/introspect', [
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'token' => $jwt,
    ])->assertOk();

    expect($response->json())->toHaveKey('active', true)
        ->and($response->json())->not->toHaveKey('sub')
        ->and($response->json())->not->toHaveKey('exp');
});

it('reports active for a valid access token of the same client', function () {
    [$jwt, $token] = issueAccessTokenViaPersonalClient($this);
    $token->forceFill(['client_id' => $this->client->id])->save();

    $this->postJson('/oauth/introspect', [
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'token' => $jwt,
    ])->assertOk()->assertJson([
        'active' => true,
        'token_type' => 'Bearer',
        'client_id' => $this->client->id,
        'sub' => (string) $this->user->id,
        'scope' => 'openid email',
    ]);
});

it('reports inactive for revoked tokens', function () {
    [$jwt, $token] = issueAccessTokenViaPersonalClient($this);
    $token->forceFill(['client_id' => $this->client->id])->save();
    $token->revoke();

    $this->postJson('/oauth/introspect', [
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'token' => $jwt,
    ])->assertOk()->assertExactJson(['active' => false]);
});

it('reports inactive for garbage tokens without leaking errors', function () {
    $this->postJson('/oauth/introspect', [
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'token' => 'not-a-token',
    ])->assertOk()->assertExactJson(['active' => false]);
});

it('reports inactive for tokens belonging to another client', function () {
    [$jwt] = issueAccessTokenViaPersonalClient($this);

    $this->postJson('/oauth/introspect', [
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'token' => $jwt,
    ])->assertOk()->assertExactJson(['active' => false]);
});

it('reports active for a valid refresh token of the same client', function () {
    [$refreshTokenValue] = issueRefreshToken($this);

    $this->postJson('/oauth/introspect', [
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'token' => $refreshTokenValue,
        'token_type_hint' => 'refresh_token',
    ])->assertOk()->assertJson([
        'active' => true,
        'client_id' => $this->client->id,
        'sub' => (string) $this->user->id,
    ])->assertJsonStructure(['active', 'client_id', 'sub', 'exp']);
});

it('reports inactive for a revoked refresh token', function () {
    [$refreshTokenValue, $refreshToken] = issueRefreshToken($this);
    $refreshToken->revoke();

    $this->postJson('/oauth/introspect', [
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'token' => $refreshTokenValue,
        'token_type_hint' => 'refresh_token',
    ])->assertOk()->assertExactJson(['active' => false]);
});

it('reports inactive for a garbage refresh token without leaking errors', function () {
    $this->postJson('/oauth/introspect', [
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'token' => 'not-a-token',
        'token_type_hint' => 'refresh_token',
    ])->assertOk()->assertExactJson(['active' => false]);
});

it('reports inactive for a refresh token belonging to another client', function () {
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.test/cb']);
    [$refreshTokenValue] = issueRefreshToken($this, (string) $other->id);

    $this->postJson('/oauth/introspect', [
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'token' => $refreshTokenValue,
        'token_type_hint' => 'refresh_token',
    ])->assertOk()->assertExactJson(['active' => false]);
});
