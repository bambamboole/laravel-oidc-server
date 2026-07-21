<?php
declare(strict_types=1);

/**
 * RFC 8693 (token exchange) + RFC 9068 (issued access token) — session-token → browser-token issuance
 */

use Bambamboole\LaravelOidc\Facades\Oidc;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Laravel\Passport\ClientRepository;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->appClient = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://app.test/cb']);
    $this->appClient->forceFill(['allowed_exchange_audiences' => json_encode(['https://api.orders.test'])])->save();
    config(['oidc.first_party.client_id' => (string) $this->appClient->id, 'app.url' => 'https://op.test']);
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->startSession();
});

it('issues an audience-scoped token for the session user', function () {
    $this->actingAs($this->user);

    $issued = Oidc::issueScopedToken('https://api.orders.test', ['openid']);

    expect($issued->audience)->toBe('https://api.orders.test')
        ->and($issued->scopes)->toBe(['openid'])
        ->and($issued->tokenType)->toBe('Bearer');

    $parsed = (new Parser(new JoseEncoder))->parse($issued->accessToken);

    if (! $parsed instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    expect($parsed->headers()->get('typ'))->toBe('at+jwt')
        ->and($parsed->claims()->get('aud'))->toBe(['https://api.orders.test'])
        ->and($parsed->claims()->get('sub'))->toBe((string) $this->user->id);
    expect((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(SigningKeys::publicKey()))))->toBeTrue();
});

it('throws when there is no session token (unauthenticated)', function () {
    Oidc::issueScopedToken('https://api.orders.test', ['openid']);
})->throws(RuntimeException::class);
