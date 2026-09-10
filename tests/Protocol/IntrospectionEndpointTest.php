<?php

declare(strict_types=1);

/**
 * RFC 7662 (OAuth 2.0 Token Introspection)
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->secret = $this->client->plainSecret;
});

/**
 * @return array{0: string, 1: AccessToken}
 */
function issueAccessTokenViaPersonalClient(mixed $test): array
{
    app(ClientRepository::class)->createPersonalAccessGrantClient('PAT');
    $result = $test->user->createToken('t', ['openid', 'email']);

    $token = $result->token;

    if (! $token instanceof AccessToken) {
        throw new RuntimeException('Expected the personal access token to be persisted.');
    }

    return [$result->accessToken, $token];
}

/**
 * @param  array<string, mixed>  $parameters
 * @return TestResponse<Response>
 */
function introspect(mixed $test, array $parameters): TestResponse
{
    return $test->postJson('/realms/default/oauth/introspect', [
        'client_id' => $test->client->id,
        'client_secret' => $test->secret,
        ...$parameters,
    ]);
}

it('rejects requests without client authentication', function () {
    $this->postJson('/realms/default/oauth/introspect', ['token' => 'x'])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_client')
        ->assertHeader('WWW-Authenticate', 'Basic realm="default"');
});

// RFC 7662 §2.3
it('rejects a request without a token parameter', function () {
    introspect($this, [])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
    introspect($this, ['token' => ''])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
});

it('omits sub and exp when the token has no user or expiry', function () {
    [$jwt, $token] = issueAccessTokenViaPersonalClient($this);
    $token->forceFill(['client_id' => $this->client->id, 'user_id' => null, 'expires_at' => null])->save();

    $response = introspect($this, ['token' => $jwt])->assertOk();

    expect($response->json())->toHaveKey('active', true)
        ->and($response->json())->not->toHaveKey('sub')
        ->and($response->json())->not->toHaveKey('exp');
});

// RFC 7662 §2.2 — members of an active access token, with the RFC 9068 §2.2 claims of the JWT
it('reports active for a valid access token of the same client', function () {
    config(['app.url' => 'https://op.test']);
    [$jwt, $token] = issueAccessTokenViaPersonalClient($this);
    $token->forceFill(['client_id' => $this->client->id])->save();
    $claims = parseAccessToken($jwt)->claims();

    $response = introspect($this, ['token' => $jwt])->assertOk()->assertExactJson([
        'active' => true,
        'token_type' => 'Bearer',
        'client_id' => $this->client->id,
        'sub' => (string) $this->user->id,
        'scope' => 'openid email',
        'exp' => $token->expires_at?->getTimestamp(),
        'iat' => $claims->get('iat')->getTimestamp(),
        'nbf' => $claims->get('nbf')->getTimestamp(),
        'jti' => $token->id,
        'iss' => 'https://op.test/realms/default',
        'aud' => $claims->get('aud'),
    ]);

    expect($response->json('aud'))->toBeArray()->not->toBeEmpty();
});

it('reports inactive for revoked tokens', function () {
    [$jwt, $token] = issueAccessTokenViaPersonalClient($this);
    $token->forceFill(['client_id' => $this->client->id])->save();
    $token->forceFill(['revoked' => true])->save();

    introspect($this, ['token' => $jwt])->assertOk()->assertExactJson(['active' => false]);
});

it('reports inactive for garbage tokens without leaking errors', function () {
    introspect($this, ['token' => 'not-a-token'])->assertOk()->assertExactJson(['active' => false]);
});

it('reports inactive for tokens belonging to another client', function () {
    [$jwt] = issueAccessTokenViaPersonalClient($this);

    introspect($this, ['token' => $jwt])->assertOk()->assertExactJson(['active' => false]);
});

it('reports active for a token that names the caller in its audience', function () {
    $requester = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Requester', ['https://req.test/cb']);

    $jwt = app(AccessTokenMinter::class)->mint(
        (string) $this->user->id, $requester->client_id, ['openid'], new DateInterval('PT1H'), [(string) $this->client->id],
    )->toString();

    introspect($this, ['token' => $jwt])->assertOk()->assertJson([
        'active' => true,
        'client_id' => (string) $requester->id,
        'sub' => (string) $this->user->id,
        'aud' => [(string) $this->client->id],
    ]);
});

// RFC 7662 §2.2 — a refresh token has no token_type; iss is the realm's
it('reports active for a valid refresh token of the same client', function () {
    config(['app.url' => 'https://op.test']);
    [$refreshTokenValue, $refreshToken] = issueRefreshToken($this);

    introspect($this, ['token' => $refreshTokenValue, 'token_type_hint' => 'refresh_token'])->assertOk()->assertExactJson([
        'active' => true,
        'scope' => 'openid',
        'client_id' => $this->client->id,
        'sub' => (string) $this->user->id,
        'exp' => $refreshToken->expires_at?->getTimestamp(),
        'iss' => 'https://op.test/realms/default',
    ]);
});

// RFC 7662 §2.1 — token_type_hint only orders the lookup
it('finds a refresh token presented with an access_token hint', function () {
    [$refreshTokenValue] = issueRefreshToken($this);

    introspect($this, ['token' => $refreshTokenValue, 'token_type_hint' => 'access_token'])
        ->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonMissingPath('token_type');
});

it('finds an access token presented with a refresh_token hint', function () {
    [$jwt, $token] = issueAccessTokenViaPersonalClient($this);
    $token->forceFill(['client_id' => $this->client->id])->save();

    introspect($this, ['token' => $jwt, 'token_type_hint' => 'refresh_token'])
        ->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonPath('token_type', 'Bearer');
});

it('ignores a token_type_hint it does not know', function () {
    [$refreshTokenValue] = issueRefreshToken($this);

    introspect($this, ['token' => $refreshTokenValue, 'token_type_hint' => 'urn:example:unknown'])
        ->assertOk()
        ->assertJsonPath('active', true);
});

it('reports inactive for a revoked refresh token', function () {
    [$refreshTokenValue, $refreshToken] = issueRefreshToken($this);
    $refreshToken->forceFill(['revoked' => true])->save();

    introspect($this, ['token' => $refreshTokenValue, 'token_type_hint' => 'refresh_token'])
        ->assertOk()
        ->assertExactJson(['active' => false]);
});

it('reports inactive for a garbage refresh token without leaking errors', function () {
    introspect($this, ['token' => 'not-a-token', 'token_type_hint' => 'refresh_token'])
        ->assertOk()
        ->assertExactJson(['active' => false]);
});

it('reports inactive for a refresh token belonging to another client', function () {
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.test/cb']);
    [$refreshTokenValue] = issueRefreshToken($this, (string) $other->id);

    introspect($this, ['token' => $refreshTokenValue, 'token_type_hint' => 'refresh_token'])
        ->assertOk()
        ->assertExactJson(['active' => false]);
});
