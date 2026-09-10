<?php

declare(strict_types=1);

/**
 * postLogin hook pipeline contract: ordering, fail-closed, protected id_token and access-token claim names
 */

use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginApi;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\NullDeviceRecognizer;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PostLoginPipeline;
use Illuminate\Http\Request;
use Workbench\App\Models\User;

/** @param list<string> $amr */
function makeLoginEvent(array $amr = ['pwd']): LoginEvent
{
    $user = User::create(['name' => 'M', 'email' => 'm'.uniqid().'@example.com', 'password' => 'x']);

    return new LoginEvent(
        user: $user, client: null, scopes: ['openid'], requestedAcrValues: [],
        ip: null, userAgent: null, amr: $amr, authTime: null,
        recognizer: new NullDeviceRecognizer, request: Request::create('/', 'POST'),
    );
}

it('runs registered hooks in order and returns the api', function () {
    $pipeline = new PostLoginPipeline;
    $pipeline->register(fn (LoginEvent $e, LoginApi $api) => $api->setIdTokenClaim('a', 1));
    $pipeline->register(fn (LoginEvent $e, LoginApi $api) => $api->requireMfa());

    $api = $pipeline->run(makeLoginEvent());

    expect($api->idTokenClaims())->toBe(['a' => 1])
        ->and($api->mfaRequired())->toBeTrue()
        ->and($api->isDenied())->toBeFalse();
});

it('fails closed when a hook throws', function () {
    $pipeline = new PostLoginPipeline;
    $pipeline->register(function (): void {
        throw new RuntimeException('boom');
    });
    $pipeline->register(fn (LoginEvent $e, LoginApi $api) => $api->setIdTokenClaim('never', 1));

    $api = $pipeline->run(makeLoginEvent());

    expect($api->isDenied())->toBeTrue()
        ->and($api->denyReason())->toBe('post_login_error')
        ->and($api->idTokenClaims())->toBe([]); // later hook skipped
});

it('refuses protected id_token and access-token claim names from hooks', function () {
    $api = new LoginApi;

    $api->setIdTokenClaim('groups', ['admin']);
    $api->setIdTokenClaim('sub', 'attacker');
    $api->setIdTokenClaim('amr', ['forged']);
    $api->setIdTokenClaim('sid', 'forged');

    $api->setAccessTokenClaim('tier', 'gold');

    foreach (['amr', 'client_id', 'scope', 'scopes', 'cnf', 'act', 'sid'] as $claim) {
        $api->setAccessTokenClaim($claim, 'forged');
    }

    expect($api->idTokenClaims())->toBe(['groups' => ['admin']])
        ->and($api->accessTokenClaims())->toBe(['tier' => 'gold']);
});
