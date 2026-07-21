<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Pipeline\LoginApi;
use Bambamboole\LaravelOidc\Auth\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Auth\Pipeline\NullDeviceRecognizer;
use Bambamboole\LaravelOidc\Auth\Pipeline\PostLoginPipeline;
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
