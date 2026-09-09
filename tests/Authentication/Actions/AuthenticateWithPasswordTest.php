<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Actions\AuthenticateWithPassword;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Workbench\App\Models\User;

function passwordUserProvider(): UserProvider
{
    return Auth::createUserProvider('users');
}

it('returns the user for valid credentials regardless of email case', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('secret-password')]);

    $result = app(AuthenticateWithPassword::class)(passwordUserProvider(), 'email', 'M@Example.com', 'secret-password');

    expect($result?->is($user))->toBeTrue();
});

it('returns null and audits a failed login for a wrong password', function () {
    $audit = fakeAudit();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('secret-password')]);

    $result = app(AuthenticateWithPassword::class)(passwordUserProvider(), 'email', 'm@example.com', 'nope');

    expect($result)->toBeNull();
    $audit->assertRecorded(AuditEventType::LoginFailed, fn ($event) => $event->userId === (string) $user->id
        && $event->context['reason'] === 'invalid_credentials');
});

it('returns null and audits without a user id for an unknown username', function () {
    $audit = fakeAudit();

    expect(app(AuthenticateWithPassword::class)(passwordUserProvider(), 'email', 'ghost@example.com', 'x'))->toBeNull();
    $audit->assertRecorded(AuditEventType::LoginFailed, fn ($event) => $event->userId === null
        && $event->context['username'] === 'ghost@example.com');
});
