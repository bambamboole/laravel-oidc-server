<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Token\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Token\SigningKeyGenerator;
use Bambamboole\LaravelOidc\Server\Token\SigningKeys;
use Bambamboole\LaravelOidc\Server\Token\TokenInspector;
use Laravel\Passport\ClientRepository;
use Workbench\App\Models\User;

function mintInspectorToken(): string
{
    $user = User::create(['name' => 'M', 'email' => 'm'.uniqid().'@example.com', 'password' => 'x']);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://rp.test/cb']);

    return app(AccessTokenMinter::class)
        ->mint((string) $user->id, $client, ['openid'], new DateInterval('PT1H'))
        ->toString();
}

it('validates tokens signed by a previous key listed in additional_public_keys', function () {
    $jwt = mintInspectorToken();
    $previousPublicKey = SigningKeys::publicKey();

    $rotated = (new SigningKeyGenerator)->generate();
    config([
        'oidc.private_key' => $rotated->privateKeyPem,
        'oidc.public_key' => $rotated->publicKeyPem,
        'oidc.additional_public_keys' => [$previousPublicKey],
    ]);

    expect(app(TokenInspector::class)->parse($jwt))->not->toBeNull();
});

it('rejects tokens signed by a key that is neither current nor retained', function () {
    $jwt = mintInspectorToken();

    $rotated = (new SigningKeyGenerator)->generate();
    config([
        'oidc.private_key' => $rotated->privateKeyPem,
        'oidc.public_key' => $rotated->publicKeyPem,
        'oidc.additional_public_keys' => [],
    ]);

    expect(app(TokenInspector::class)->parse($jwt))->toBeNull();
});

function tokenInspectorBase64Url(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

it('rejects an unsigned token with header alg none', function () {
    $jwt = tokenInspectorBase64Url((string) json_encode(['typ' => 'at+jwt', 'alg' => 'none']))
        .'.'.tokenInspectorBase64Url((string) json_encode(['jti' => 'forged', 'sub' => '1', 'exp' => time() + 3600]))
        .'.';

    expect(app(TokenInspector::class)->parse($jwt))->toBeNull();
});

it('rejects an HS256 token signed with the server public key as the HMAC secret', function () {
    $header = tokenInspectorBase64Url((string) json_encode(['typ' => 'at+jwt', 'alg' => 'HS256']));
    $payload = tokenInspectorBase64Url((string) json_encode(['jti' => 'forged', 'sub' => '1', 'exp' => time() + 3600]));
    $signature = tokenInspectorBase64Url(hash_hmac('sha256', $header.'.'.$payload, SigningKeys::publicKey(), true));

    expect(app(TokenInspector::class)->parse($header.'.'.$payload.'.'.$signature))->toBeNull();
});

it('resolves the persisted token from an already-parsed JWT', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://rp.test/cb']);

    $entity = app(AccessTokenMinter::class)->mint(
        (string) $user->id, $client, ['openid'], new DateInterval('PT1H'), ['https://api.test'],
    );

    $inspector = app(TokenInspector::class);
    $parsed = $inspector->parse($entity->toString());

    $token = $inspector->tokenForParsed($parsed);

    expect($token)->not->toBeNull()
        ->and($token->getKey())->toBe($parsed->claims()->get('jti'))
        ->and((string) $token->getAttribute('user_id'))->toBe((string) $user->id);
});
