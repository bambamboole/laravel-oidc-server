<?php
declare(strict_types=1);

/**
 * RFC 9068 (access token) + RFC 7009 (revocation) — session root-token lifecycle (package two-token model)
 */

use Bambamboole\LaravelOidc\Contracts\SessionTokenProvider;
use Bambamboole\LaravelOidc\Token\TokenInspector;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Laravel\Passport\ClientRepository;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->startSession();
});

it('does not throw and establishes no token when the first-party client id is empty', function () {
    config(['oidc.first_party.client_id' => '']);

    event(new Login('web', $this->user, false));

    expect(session('oidc.session_token'))->toBeNull();
});

it('does not throw when the configured client id is stale, establishing no token', function () {
    config(['oidc.first_party.client_id' => 'nonexistent-client-id']);

    event(new Login('web', $this->user, false));

    expect(session('oidc.session_token'))->toBeNull();
});

it('establishes a token on login when a valid first-party client is configured', function () {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://app.test/cb']);
    config(['oidc.first_party.client_id' => (string) $client->id]);

    event(new Login('web', $this->user, false));

    expect(session('oidc.session_token')['jwt'] ?? null)->toBeString();
});

it('revokes and clears the token on logout', function () {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://app.test/cb']);
    config(['oidc.first_party.client_id' => (string) $client->id]);
    app(SessionTokenProvider::class)->establish($this->user);
    $jwt = session('oidc.session_token')['jwt'];

    event(new Logout('web', $this->user));

    expect(session('oidc.session_token'))->toBeNull();
    $dbToken = app(TokenInspector::class)->accessToken($jwt);
    expect($dbToken === null || (bool) $dbToken->getAttribute('revoked'))->toBeTrue();
});
