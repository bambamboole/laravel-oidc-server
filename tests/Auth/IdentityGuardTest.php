<?php

declare(strict_types=1);

use Workbench\App\Models\User;

it('registers package authentication under the identity guard and auth prefix', function () {
    expect(config('oidc.auth.guard'))->toBe('identity')
        ->and(config('passport.guard'))->toBe('identity')
        ->and(config('auth.guards.identity'))->toBe([
            'driver' => 'session',
            'provider' => 'users',
        ])
        ->and(route('identity.login', absolute: false))->toBe('/auth/login')
        ->and(route('identity.password.reset', ['token' => 'token'], absolute: false))->toBe('/auth/reset-password/token')
        ->and(route('identity.two-factor.login', absolute: false))->toBe('/auth/two-factor-challenge')
        ->and(config('oidc.auth.two_factor'))->not->toHaveKeys(['requires_password_confirmation', 'throttle'])
        ->and(app('router')->getRoutes()->getByName('identity.two-factor.enable')->middleware())
        ->toContain('Illuminate\Auth\Middleware\RequirePassword:identity.password.confirm')
        ->and(app('router')->getRoutes()->getByName('identity.two-factor.login.store')->middleware())
        ->toContain('throttle:5,1')
        ->and(app('router')->getRoutes()->getByName('login'))->toBeNull();
});

it('establishes only the identity session through the credential login route', function () {
    $user = User::create([
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => bcrypt('password'),
    ]);

    $this->post(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'password',
    ])->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user, 'identity');
    $this->assertGuest('web');
});

it('redirects identity-protected routes to the configured identity login destination', function () {
    config(['oidc.login_route' => 'identity.login']);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'web')
        ->get('/auth/user/confirmed-password-status')
        ->assertRedirect('/auth/login');

    $this->assertAuthenticatedAs($user, 'web');
    $this->assertGuest('identity');
});
