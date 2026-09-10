<?php

declare(strict_types=1);

/**
 * RFC 8693 §2.2 (issued token), §4.1 (act chain); RFC 9068 (issued access token)
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\TokenExchanger;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Workbench\App\Models\User;

beforeEach(function (): void {
    config(['app.url' => 'https://op.test']);
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->appClient = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://app.test/cb']);
    $this->appClient->forceFill(['allowed_exchange_audiences' => ['https://api.orders.test']])->save();
    $this->root = app(AccessTokenMinter::class)
        ->mint((string) $this->user->id, $this->appClient->client_id, ['openid', 'email'], new DateInterval('PT1H'))
        ->toString();
});

it('exchanges the root token for an audience-scoped, narrowed token naming the actor', function (): void {
    $entity = app(TokenExchanger::class)->exchange($this->root, $this->appClient, 'https://api.orders.test', ['openid']);

    $parsed = parseAccessToken($entity->toString());

    expect($parsed->headers()->get('typ'))->toBe('at+jwt')
        ->and($parsed->claims()->get('aud'))->toBe(['https://api.orders.test'])
        ->and($parsed->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($parsed->claims()->get('scope'))->toBe('openid')
        ->and($parsed->claims()->get('act'))->toBe(['client_id' => $this->appClient->id])
        ->and((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(signingPublicKey()))))->toBeTrue();
});

it('rejects an invalid exchange with the matching OAuth error type', function (
    ?string $subjectToken,
    string $audience,
    array $scopes,
    string $errorType,
): void {
    expectExchangeDenied(
        fn () => app(TokenExchanger::class)->exchange($subjectToken ?? $this->root, $this->appClient, $audience, $scopes),
        $errorType,
    );
})->with([
    'unlisted target audience' => [null, 'https://evil.test', ['openid'], 'invalid_target'],
    'invalid subject token' => ['garbage', 'https://api.orders.test', ['openid'], 'invalid_grant'],
]);

it('nests the prior act claim on a chained exchange', function (): void {
    $root = app(AccessTokenMinter::class)
        ->mint((string) $this->user->id, $this->appClient->client_id, ['openid'], new DateInterval('PT1H'), actor: ['client_id' => 'client-a'])
        ->toString();

    $issued = app(TokenExchanger::class)->exchange($root, $this->appClient, 'https://api.orders.test', ['openid']);

    expect(parseAccessToken($issued->toString())->claims()->get('act'))
        ->toBe(['client_id' => $this->appClient->id, 'act' => ['client_id' => 'client-a']]);
});
