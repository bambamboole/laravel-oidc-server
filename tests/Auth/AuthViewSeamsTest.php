<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Views\EmailVerificationPrompt;
use Bambamboole\LaravelOidc\Auth\Views\EmailVerificationView;
use Bambamboole\LaravelOidc\Auth\Views\PasswordResetPrompt;
use Bambamboole\LaravelOidc\Auth\Views\PasswordResetRequestPrompt;
use Bambamboole\LaravelOidc\Auth\Views\PasswordResetRequestView;
use Bambamboole\LaravelOidc\Auth\Views\PasswordResetView;
use Bambamboole\LaravelOidc\Auth\Views\RegisterPrompt;
use Bambamboole\LaravelOidc\Auth\Views\RegisterView;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

it('renders account flow views through package seams', function () {
    app()->bind(RegisterView::class, fn () => new class implements RegisterView
    {
        public function respond(RegisterPrompt $prompt, Request $request): Response
        {
            return response('register-view');
        }
    });
    app()->bind(PasswordResetRequestView::class, fn () => new class implements PasswordResetRequestView
    {
        public function respond(PasswordResetRequestPrompt $prompt, Request $request): Response
        {
            return response('forgot-password-view');
        }
    });
    app()->bind(PasswordResetView::class, fn () => new class implements PasswordResetView
    {
        public function respond(PasswordResetPrompt $prompt, Request $request): Response
        {
            return response('reset-password-view:'.$prompt->token);
        }
    });
    app()->bind(EmailVerificationView::class, fn () => new class implements EmailVerificationView
    {
        public function respond(EmailVerificationPrompt $prompt, Request $request): Response
        {
            return response('verify-email-view');
        }
    });

    $this->get('/auth/register')->assertOk()->assertSee('register-view');
    $this->get('/auth/forgot-password')->assertOk()->assertSee('forgot-password-view');
    $this->get('/auth/reset-password/reset-token?email=m@example.com')->assertOk()->assertSee('reset-password-view:reset-token');

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')->get('/auth/email/verify')->assertOk()->assertSee('verify-email-view');
});
