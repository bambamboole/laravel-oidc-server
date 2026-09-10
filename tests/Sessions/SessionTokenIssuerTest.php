<?php

declare(strict_types=1);

/**
 * RFC 9068 (access token) + RFC 7009 (revocation) — the first-party session root token: established on login,
 * re-established per user, revoked on logout and on supersession
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Sessions\SessionTokenProvider;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\TokenInspector;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Workbench\App\Models\User;

beforeEach(function () {
    config(['oidc.session.token.guard' => 'web']);
    $this->appClient = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://app.test/cb']);
    config(['oidc.clients.first_party.client_id' => (string) $this->appClient->id]);
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->startSession();
});

function sessionTokenIsRevoked(string $jwt): bool
{
    $token = app(TokenInspector::class)->accessToken($jwt);

    return $token === null || (bool) $token->getAttribute('revoked');
}

it('establishes a persisted, signed root token for the user on login', function () {
    event(new Login('web', $this->user, false));

    $jwt = session('oidc.session_token')['jwt'] ?? null;
    expect($jwt)->toBeString();

    $parsed = parseAccessToken($jwt);

    expect($parsed->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($parsed->claims()->get('client_id'))->toBe($this->appClient->id)
        ->and($parsed->claims()->get('aud'))->toBe([app(IssuerResolver::class)->url()])
        ->and((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(signingPublicKey()))))->toBeTrue()
        ->and(app(TokenInspector::class)->accessToken($jwt))->not->toBeNull();
});

it('establishes no token when the first-party client is unset or unknown', function (string $clientId) {
    config(['oidc.clients.first_party.client_id' => $clientId]);

    event(new Login('web', $this->user, false));

    expect(session('oidc.session_token'))->toBeNull();
})->with(['empty' => '', 'unknown' => 'nonexistent-client-id']);

it('ignores logins and logouts on guards other than the owning guard', function () {
    event(new Login('admin', $this->user, false));

    expect(session('oidc.session_token'))->toBeNull();

    app(SessionTokenProvider::class)->establish($this->user);
    $jwt = session('oidc.session_token')['jwt'];

    event(new Logout('admin', $this->user));

    expect(session('oidc.session_token'))->not->toBeNull()
        ->and(sessionTokenIsRevoked($jwt))->toBeFalse();
});

it('revokes and clears the token on logout', function () {
    app(SessionTokenProvider::class)->establish($this->user);
    $jwt = session('oidc.session_token')['jwt'];

    event(new Logout('web', $this->user));

    expect(session('oidc.session_token'))->toBeNull()
        ->and(sessionTokenIsRevoked($jwt))->toBeTrue();
});

it('mints on demand and re-establishes when the stored token belongs to another user', function () {
    expect(app(SessionTokenProvider::class)->currentToken())->toBeNull();

    $this->actingAs($this->user);
    $jwt = app(SessionTokenProvider::class)->currentToken();

    expect($jwt)->toBeString()
        ->and(parseAccessToken($jwt)->claims()->get('sub'))->toBe((string) $this->user->id);

    $other = User::create(['name' => 'B', 'email' => 'b@example.com', 'password' => 'x']);
    $this->actingAs($other);

    expect(parseAccessToken((string) app(SessionTokenProvider::class)->currentToken())->claims()->get('sub'))->toBe((string) $other->id);
});

it('revokes the superseded root token when re-establishing', function () {
    $this->actingAs($this->user);
    app(SessionTokenProvider::class)->establish($this->user);
    $firstJti = session('oidc.session_token')['jti'];

    app(SessionTokenProvider::class)->establish($this->user);

    expect((bool) AccessToken::query()->whereKey($firstJti)->firstOrFail()->getAttribute('revoked'))->toBeTrue();
});
