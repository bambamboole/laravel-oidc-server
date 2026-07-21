<?php

declare(strict_types=1);

/**
 * RFC 7009 (OAuth 2.0 Token Revocation)
 */

use Laravel\Passport\ClientRepository;
use Laravel\Passport\Token;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->secret = $this->client->plainSecret;

    app(ClientRepository::class)->createPersonalAccessGrantClient('PAT', 'users');
    $result = $this->user->createToken('t', ['openid']);

    $token = $result->getToken();

    if (! $token instanceof Token) {
        throw new RuntimeException('Expected the personal access token to be persisted.');
    }

    $token->forceFill(['client_id' => $this->client->id])->save();
    $this->jwt = $result->accessToken;
    $this->token = $token;
});

it('revokes an access token for its own client', function () {
    $this->postJson('/oauth/revoke', [
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'token' => $this->jwt,
    ])->assertOk();

    expect($this->token->fresh()->revoked)->toBeTrue();
});

it('silently ignores tokens of other clients per rfc 7009', function () {
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.test/cb']);

    $this->postJson('/oauth/revoke', [
        'client_id' => $other->id,
        'client_secret' => $other->plainSecret,
        'token' => $this->jwt,
    ])->assertOk();

    expect($this->token->fresh()->revoked)->toBeFalse();
});

it('rejects unauthenticated revocation', function () {
    $this->postJson('/oauth/revoke', ['token' => $this->jwt])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_client')
        ->assertHeader('WWW-Authenticate', 'Basic realm="OIDC"');
});

it('revokes a refresh token and its linked access token for its own client', function () {
    [$refreshTokenValue, $refreshToken, $accessToken] = issueRefreshToken($this);

    $this->postJson('/oauth/revoke', [
        'client_id' => $this->client->id,
        'client_secret' => $this->secret,
        'token' => $refreshTokenValue,
        'token_type_hint' => 'refresh_token',
    ])->assertOk();

    expect($refreshToken->refresh()->getAttribute('revoked'))->toBeTrue()
        ->and($accessToken->refresh()->getAttribute('revoked'))->toBeTrue();
});

it('silently ignores refresh tokens of other clients per rfc 7009', function () {
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.test/cb']);
    [$refreshTokenValue, $refreshToken, $accessToken] = issueRefreshToken($this);

    $this->postJson('/oauth/revoke', [
        'client_id' => $other->id,
        'client_secret' => $other->plainSecret,
        'token' => $refreshTokenValue,
        'token_type_hint' => 'refresh_token',
    ])->assertOk();

    expect($refreshToken->refresh()->getAttribute('revoked'))->toBeFalse()
        ->and($accessToken->refresh()->getAttribute('revoked'))->toBeFalse();
});
