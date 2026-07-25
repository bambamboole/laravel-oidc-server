<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Testing\FakesAuthViews;
use Workbench\App\Models\User;

uses(FakesAuthViews::class);

it('binds every controller-facing auth view contract to its JSON stub', function () {
    $this->fakeAuthViews();

    $this->get(route('identity.login'))->assertOk()->assertJson(['view' => 'login']);
    $this->get(route('identity.register'))->assertOk()->assertJson(['view' => 'register']);
    $this->get(route('identity.password.request'))->assertOk()->assertJson(['view' => 'request-password-reset-link']);
    $this->get(route('identity.password.reset', ['token' => 'reset-token', 'email' => 'm@example.com']))
        ->assertOk()
        ->assertJson([
            'view' => 'reset-password',
            'prompt' => ['token' => 'reset-token', 'email' => 'm@example.com', 'status' => null],
        ]);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')
        ->get(route('identity.verification.notice'))
        ->assertOk()
        ->assertJson(['view' => 'verify-email']);

    $this->actingAs($user, 'identity')
        ->get(route('identity.password.confirm'))
        ->assertOk()
        ->assertJson(['view' => 'confirm-password']);

    auth('identity')->logout();

    $this->withSession(['login.id' => $user->getAuthIdentifier()])
        ->get(route('identity.two-factor.login'))
        ->assertOk()
        ->assertJson(['view' => 'two-factor-challenge']);
});
