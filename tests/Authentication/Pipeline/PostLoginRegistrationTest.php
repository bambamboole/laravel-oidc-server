<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginApi;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\NullDeviceRecognizer;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PostLoginPipeline;
use Illuminate\Http\Request;
use Workbench\App\Models\User;

/** @param list<string> $amr */
function makeRegistrationLoginEvent(array $amr = ['pwd']): LoginEvent
{
    $user = User::create(['name' => 'M', 'email' => 'm'.uniqid().'@example.com', 'password' => 'x']);

    return new LoginEvent(
        user: $user, client: null, scopes: ['openid'], requestedAcrValues: [],
        ip: null, userAgent: null, amr: $amr, authTime: null,
        recognizer: new NullDeviceRecognizer, request: Request::create('/', 'POST'),
    );
}

it('registers a postLogin hook on the shared pipeline', function () {
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->requireMfa());

    $api = app(PostLoginPipeline::class)->run(makeRegistrationLoginEvent());

    expect($api->mfaRequired())->toBeTrue();
});
