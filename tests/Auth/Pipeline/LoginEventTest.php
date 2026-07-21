<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Auth\Pipeline\NullDeviceRecognizer;
use Illuminate\Http\Request;
use Workbench\App\Models\User;

it('exposes login context and derives helpers', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $event = new LoginEvent(
        user: $user,
        client: null,
        scopes: ['openid', 'email'],
        requestedAcrValues: ['mfa'],
        ip: '203.0.113.9',
        userAgent: 'phpunit',
        amr: ['pwd'],
        authTime: 1700000000,
        recognizer: new NullDeviceRecognizer,
        request: Request::create('/auth/login', 'POST'),
    );

    expect($event->scopes)->toBe(['openid', 'email'])
        ->and($event->amr)->toBe(['pwd'])
        ->and($event->requestsAcr('mfa'))->toBeTrue()
        ->and($event->requestsAcr('phr'))->toBeFalse()
        ->and($event->isNewDevice())->toBeFalse();
});
