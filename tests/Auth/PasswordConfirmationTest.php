<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Views\PasswordConfirmationPrompt;
use Bambamboole\LaravelOidc\Auth\Views\PasswordConfirmationView;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

it('renders the confirm password view through the package seam', function () {
    app()->bind(PasswordConfirmationView::class, fn () => new class implements PasswordConfirmationView
    {
        public function respond(PasswordConfirmationPrompt $prompt, Request $request): Response
        {
            return response('confirm-password-view');
        }
    });

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->actingAs($user, 'identity')->get('/auth/user/confirm-password')->assertOk()->assertSee('confirm-password-view');
});

it('confirms the password and records the confirmation timestamp', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->actingAs($user, 'identity')
        ->from('/auth/user/confirm-password')
        ->post(route('identity.password.confirm.store'), ['password' => 'password'])
        ->assertRedirect('/dashboard')
        ->assertSessionHas('auth.password_confirmed_at');
});

it('rejects password confirmation with the wrong password', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->actingAs($user, 'identity')
        ->from('/auth/user/confirm-password')
        ->post(route('identity.password.confirm.store'), ['password' => 'wrong-password'])
        ->assertRedirect('/auth/user/confirm-password')
        ->assertSessionHasErrors('password');

    expect(session()->has('auth.password_confirmed_at'))->toBeFalse();
});

it('reports the confirmation status through the status endpoint', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->actingAs($user, 'identity')
        ->getJson(route('identity.password.confirmation'))
        ->assertOk()
        ->assertJson(['confirmed' => false]);

    $this->actingAs($user, 'identity')
        ->post(route('identity.password.confirm.store'), ['password' => 'password']);

    $this->actingAs($user, 'identity')
        ->getJson(route('identity.password.confirmation'))
        ->assertOk()
        ->assertJson(['confirmed' => true]);
});

it('treats an elapsed confirmation as unconfirmed', function () {
    config()->set('auth.password_timeout', 900);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time() - 1000])
        ->getJson(route('identity.password.confirmation'))
        ->assertOk()
        ->assertJson(['confirmed' => false]);
});
