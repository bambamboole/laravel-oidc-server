<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Views\LoginPrompt;
use Bambamboole\LaravelOidc\Auth\Views\LoginView;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

it('renders the login view through the package seam', function () {
    app()->bind(LoginView::class, fn () => new class implements LoginView
    {
        public function respond(LoginPrompt $prompt, Request $request): Response
        {
            return response('login-view');
        }
    });

    $this->get('/auth/login')->assertOk()->assertSee('login-view');
});

it('logs a user in with canonicalized credentials and redirects home', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $response = $this->from('/auth/login')->post(route('identity.login.store'), [
        'email' => 'M@Example.com',
        'password' => 'password',
    ]);

    $response->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($user, 'identity');
});

it('returns Fortify-compatible JSON after login', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->postJson(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'password',
    ])->assertOk();

    $this->assertAuthenticatedAs($user, 'identity');
});

it('rejects invalid credentials with a validation error', function () {
    User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->from('/auth/login')
        ->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'wrong-password'])
        ->assertRedirect('/auth/login')
        ->assertSessionHasErrors('email');

    $this->assertGuest('identity');
});

it('sets a remember cookie when remember is requested', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $response = $this->post(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'password',
        'remember' => true,
    ]);

    $this->assertAuthenticatedAs($user, 'identity');
    $response->assertCookie(auth()->guard('identity')->getRecallerName());
});

it('throttles repeated login attempts', function () {
    User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    foreach (range(1, 5) as $ignored) {
        $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'wrong-password']);
    }

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'wrong-password'])
        ->assertStatus(429);
});

it('records the pwd method on a successful password login', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->post(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'password',
    ]);

    $this->assertAuthenticatedAs($user, 'identity');
    expect(session()->get('oidc.amr'))->toBe(['pwd']);
});
