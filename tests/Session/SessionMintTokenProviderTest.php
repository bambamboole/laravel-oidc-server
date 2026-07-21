<?php
declare(strict_types=1);

/**
 * RFC 9068 (access token) + RFC 7009 (revocation) — session root-token lifecycle (package two-token model)
 */

use Bambamboole\LaravelOidc\Contracts\SessionTokenProvider;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Bambamboole\LaravelOidc\Token\TokenInspector;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Workbench\App\Models\User;

function parseSessionToken(string $jwt): UnencryptedToken
{
    $parsed = (new Parser(new JoseEncoder))->parse($jwt);

    if (! $parsed instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $parsed;
}

beforeEach(function () {
    $this->appClient = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://app.test/cb']);
    config(['oidc.first_party.client_id' => (string) $this->appClient->id]);
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->startSession();
});

it('establishes a persisted root token for the user, stored in the session', function () {
    $this->actingAs($this->user);
    app(SessionTokenProvider::class)->establish($this->user);

    $jwt = session('oidc.session_token')['jwt'] ?? null;
    expect($jwt)->toBeString();

    $parsed = parseSessionToken($jwt);
    expect($parsed->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($parsed->claims()->get('client_id'))->toBe($this->appClient->id)
        ->and($parsed->claims()->get('aud'))->toBe([$this->appClient->id]);

    expect((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(SigningKeys::publicKey()))))->toBeTrue();
    expect(app(TokenInspector::class)->accessToken($jwt))->not->toBeNull();
});

it('currentToken self-heals by minting when none is stored', function () {
    $this->actingAs($this->user);

    $jwt = app(SessionTokenProvider::class)->currentToken();
    expect($jwt)->toBeString()
        ->and(parseSessionToken($jwt)->claims()->get('sub'))->toBe((string) $this->user->id);
});

it('currentToken returns null without an authenticated user', function () {
    expect(app(SessionTokenProvider::class)->currentToken())->toBeNull();
});

it('re-establishes for the current user when the stored token belongs to a different user', function () {
    $userB = User::create(['name' => 'B', 'email' => 'b@example.com', 'password' => 'x']);

    $this->actingAs($this->user);
    app(SessionTokenProvider::class)->establish($this->user);

    $this->actingAs($userB);
    $jwt = app(SessionTokenProvider::class)->currentToken();

    expect($jwt)->toBeString()
        ->and(parseSessionToken($jwt)->claims()->get('sub'))->toBe((string) $userB->id);
});

it('revokes the superseded root token when re-establishing', function () {
    $this->actingAs($this->user);
    app(SessionTokenProvider::class)->establish($this->user);
    $firstJti = session('oidc.session_token')['jti'];

    app(SessionTokenProvider::class)->establish($this->user);

    $first = Passport::token()->newQuery()->whereKey($firstJti)->first();
    expect((bool) $first->getAttribute('revoked'))->toBeTrue();
});

it('forget revokes the root token and clears the session', function () {
    $this->actingAs($this->user);
    app(SessionTokenProvider::class)->establish($this->user);
    $jwt = session('oidc.session_token')['jwt'];

    app(SessionTokenProvider::class)->forget();

    expect(session('oidc.session_token'))->toBeNull();
    $dbToken = app(TokenInspector::class)->accessToken($jwt);
    expect($dbToken === null || (bool) $dbToken->getAttribute('revoked'))->toBeTrue();
});
