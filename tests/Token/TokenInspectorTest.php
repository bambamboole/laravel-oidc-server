<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Token\AccessTokenMinter;
use Bambamboole\LaravelOidc\Token\TokenInspector;
use Laravel\Passport\ClientRepository;
use Workbench\App\Models\User;

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
