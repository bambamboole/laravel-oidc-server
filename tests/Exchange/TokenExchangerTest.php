<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Exchange\IssuedToken;
use Bambamboole\LaravelOidc\Exchange\TokenExchanger;
use Bambamboole\LaravelOidc\Token\AccessTokenMinter;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Laravel\Passport\ClientRepository;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\Exception\OAuthServerException;
use Workbench\App\Models\User;

beforeEach(function () {
    config(['app.url' => 'https://op.test']);
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    // The app client performs the exchange; its allowlist authorizes the target audience.
    $this->appClient = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://app.test/cb']);
    $this->appClient->forceFill(['allowed_exchange_audiences' => json_encode(['https://api.orders.test'])])->save();
    // A root token issued TO the app client (aud defaults to the app client id) — reciprocity passes via client_id match.
    $this->root = app(AccessTokenMinter::class)
        ->mint((string) $this->user->id, $this->appClient, ['openid', 'email'], new DateInterval('PT1H'))
        ->toString();
});

function parseExchanged(string $jwt): UnencryptedToken
{
    $parsed = (new Parser(new JoseEncoder))->parse($jwt);

    if (! $parsed instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $parsed;
}

it('exchanges the root token for an audience-scoped, narrowed token', function () {
    $entity = app(TokenExchanger::class)->exchange($this->root, $this->appClient, 'https://api.orders.test', ['openid']);

    $parsed = parseExchanged($entity->toString());
    expect($parsed->headers()->get('typ'))->toBe('at+jwt')
        ->and($parsed->claims()->get('aud'))->toBe(['https://api.orders.test'])
        ->and($parsed->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($parsed->claims()->get('scope'))->toBe('openid')
        ->and($parsed->claims()->get('act'))->toBe(['client_id' => $this->appClient->id]);

    expect((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(SigningKeys::publicKey()))))->toBeTrue();
});

it('wraps the entity into an IssuedToken', function () {
    $entity = app(TokenExchanger::class)->exchange($this->root, $this->appClient, 'https://api.orders.test', ['openid']);
    $issued = IssuedToken::fromEntity($entity, 'https://api.orders.test');

    expect($issued->tokenType)->toBe('Bearer')
        ->and($issued->audience)->toBe('https://api.orders.test')
        ->and($issued->scopes)->toBe(['openid'])
        ->and($issued->expiresIn)->toBeGreaterThan(0)
        ->and($issued->accessToken)->toBe($entity->toString());
});

it('rejects an unlisted target audience with invalid_target', function () {
    try {
        app(TokenExchanger::class)->exchange($this->root, $this->appClient, 'https://evil.test', ['openid']);
        $this->fail('expected rejection');
    } catch (OAuthServerException $e) {
        expect($e->getErrorType())->toBe('invalid_target');
    }
});

it('rejects scope widening with invalid_scope', function () {
    try {
        app(TokenExchanger::class)->exchange($this->root, $this->appClient, 'https://api.orders.test', ['admin']);
        $this->fail('expected rejection');
    } catch (OAuthServerException $e) {
        expect($e->getErrorType())->toBe('invalid_scope');
    }
});

it('rejects an invalid subject token with invalid_grant', function () {
    try {
        app(TokenExchanger::class)->exchange('garbage', $this->appClient, 'https://api.orders.test', ['openid']);
        $this->fail('expected rejection');
    } catch (OAuthServerException $e) {
        expect($e->getErrorType())->toBe('invalid_grant');
    }
});

it('nests the prior act claim on a chained exchange', function () {
    $rootEntity = app(AccessTokenMinter::class)->mint((string) $this->user->id, $this->appClient, ['openid'], new DateInterval('PT1H'));
    $rootEntity->setActor(['client_id' => 'client-a']);
    $root = $rootEntity->toString();

    $issued = app(TokenExchanger::class)->exchange($root, $this->appClient, 'https://api.orders.test', ['openid']);

    $act = parseExchanged($issued->toString())->claims()->get('act');
    expect($act)->toBe(['client_id' => $this->appClient->id, 'act' => ['client_id' => 'client-a']]);
});
