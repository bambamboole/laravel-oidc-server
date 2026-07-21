<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Responses\IdTokenResponse;
use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\Bridge\Client as BridgeClient;
use Laravel\Passport\Bridge\Scope as BridgeScope;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\CryptKey;
use Workbench\App\Models\User;

function buildOpenidAccessToken(User $user): AccessToken
{
    $client = new BridgeClient('rp', 'RP', ['https://rp.test/callback']);
    $token = new AccessToken((string) $user->id, [new BridgeScope('openid')], $client);
    $token->setIdentifier('tid');
    $token->setExpiryDateTime(new DateTimeImmutable('+1 hour'));
    $token->setPrivateKey(new CryptKey(__DIR__.'/../fixtures/oauth-private.key', null, false));

    return $token;
}

/**
 * @return array<string, mixed>
 */
function extraParams(IdTokenResponse $response, AccessToken $accessToken): array
{
    return (new ReflectionMethod($response, 'getExtraParams'))->invoke($response, $accessToken);
}

function parseResponseIdToken(string $jwt): UnencryptedToken
{
    $token = (new Parser(new JoseEncoder))->parse($jwt);

    if (! $token instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted JWT.');
    }

    return $token;
}

it('clears the nonce and auth_time after the first issuance', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $accessToken = buildOpenidAccessToken($user);

    $response = app(IdTokenResponse::class);
    $response->setNonce('n0nce');
    $response->setAuthTime(1234567890);

    $first = parseResponseIdToken(extraParams($response, $accessToken)['id_token']);

    expect($first->claims()->get('nonce'))->toBe('n0nce')
        ->and($first->claims()->get('auth_time'))->toBe(1234567890);

    $second = parseResponseIdToken(extraParams($response, $accessToken)['id_token']);

    expect($second->claims()->has('nonce'))->toBeFalse()
        ->and($second->claims()->has('auth_time'))->toBeFalse();
});

it('clears amr after emitting so it does not leak to the next issuance', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $accessToken = buildOpenidAccessToken($user);

    $response = app(IdTokenResponse::class);
    $response->setAmr(['pwd', 'otp']);

    expect((new ReflectionProperty($response, 'amr'))->getValue($response))->toBe(['pwd', 'otp']);

    $first = parseResponseIdToken(extraParams($response, $accessToken)['id_token']);

    expect($first->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and((new ReflectionProperty($response, 'amr'))->getValue($response))->toBe([]);

    $second = parseResponseIdToken(extraParams($response, $accessToken)['id_token']);

    expect($second->claims()->has('amr'))->toBeFalse();
});
