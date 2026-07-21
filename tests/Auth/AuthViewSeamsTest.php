<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Facades\Oidc;
use Illuminate\Http\Request;
use Workbench\App\Models\User;

it('renders account flow views through package seams', function () {
    Oidc::registerView(fn (Request $request) => response('register-view'));
    Oidc::requestPasswordResetLinkView(fn (Request $request) => response('forgot-password-view'));
    Oidc::resetPasswordView(fn (Request $request) => response('reset-password-view:'.$request->route('token')));
    Oidc::verifyEmailView(fn (Request $request) => response('verify-email-view'));

    $this->get('/auth/register')->assertOk()->assertSee('register-view');
    $this->get('/auth/forgot-password')->assertOk()->assertSee('forgot-password-view');
    $this->get('/auth/reset-password/reset-token?email=m@example.com')->assertOk()->assertSee('reset-password-view:reset-token');

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')->get('/auth/email/verify')->assertOk()->assertSee('verify-email-view');
});
