<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Facades\Oidc;
use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Workbench\App\Models\User;

it('registers a user through the package action seam and logs them in', function () {
    Event::fake([Registered::class]);

    Oidc::createUsersUsing(function (array $input): Authenticatable {
        return User::create([
            'name' => $input['name'],
            'email' => $input['email'],
            'password' => Hash::make($input['password']),
        ]);
    });

    $response = $this->from('/auth/register')->post(route('identity.register.store'), [
        'name' => 'M',
        'email' => 'MixedCase@Example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ]);

    $user = User::where('email', 'mixedcase@example.com')->firstOrFail();

    $response->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($user, 'identity');
    Event::assertDispatched(Registered::class, fn (Registered $event): bool => $event->user->is($user));
});

it('returns Fortify-compatible JSON after registration', function () {
    Oidc::createUsersUsing(function (array $input): Authenticatable {
        return User::create([
            'name' => $input['name'],
            'email' => $input['email'],
            'password' => Hash::make($input['password']),
        ]);
    });

    $this->postJson(route('identity.register.store'), [
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ])->assertCreated();

    $this->assertAuthenticated('identity');
});
