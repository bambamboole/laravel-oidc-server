<?php
// tests/Session/StartOidcSessionTest.php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Models\OidcSession;
use Illuminate\Support\Facades\Auth;
use Workbench\App\Models\User;

it('records oidc metadata without starting the session store on an oidc guard login', function () {
    $session = app('session.store');
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    expect($session->isStarted())->toBeFalse();

    Auth::guard((string) config('passport.guard'))->login($user);

    expect($session->get('oidc.auth_time'))->toBeInt()
        ->and($session->get('oidc.sid'))->toBeString()
        ->and($session->isStarted())->toBeFalse()
        ->and(OidcSession::query()->where('user_id', (string) $user->id)->count())->toBe(1);
});

it('does not create oidc metadata or a session when authenticating once by id', function () {
    $user = User::create(['name' => 'M', 'email' => 'm2@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    Auth::guard((string) config('passport.guard'))->onceUsingId($user->id);

    $session = app('session.store');

    expect($session->has('oidc.auth_time'))->toBeFalse()
        ->and($session->has('oidc.sid'))->toBeFalse()
        ->and($session->isStarted())->toBeFalse()
        ->and(OidcSession::query()->count())->toBe(0);
});

it('does not create or overwrite oidc metadata on another guard login', function () {
    $session = app('session.store');
    $user = User::create(['name' => 'M', 'email' => 'm3@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    Auth::guard('web')->login($user);

    expect($session->has('oidc.auth_time'))->toBeFalse()
        ->and($session->has('oidc.sid'))->toBeFalse()
        ->and(OidcSession::query()->count())->toBe(0);

    $session->put([
        'oidc.auth_time' => 1_234_567_890,
        'oidc.sid' => 'existing-sid',
    ]);

    Auth::guard('web')->login($user);

    expect($session->get('oidc.auth_time'))->toBe(1_234_567_890)
        ->and($session->get('oidc.sid'))->toBe('existing-sid')
        ->and($session->isStarted())->toBeFalse()
        ->and(OidcSession::query()->count())->toBe(0);
});
