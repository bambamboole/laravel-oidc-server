<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Views\EmailVerificationPrompt;
use Bambamboole\LaravelOidc\Server\Authentication\Views\EmailVerificationView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\LoginPrompt;
use Bambamboole\LaravelOidc\Server\Authentication\Views\LoginView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordConfirmationView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordResetPrompt;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordResetRequestPrompt;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordResetRequestView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordResetView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\RegisterView;
use Bambamboole\LaravelOidc\Server\Credentials\TotpFactorProvider;
use Bambamboole\LaravelOidc\Server\Credentials\Views\TwoFactorChallengePrompt;
use Bambamboole\LaravelOidc\Server\Credentials\Views\TwoFactorChallengeView;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

it('renders every auth page through its package view seam', function (): void {
    app()->bind(LoginView::class, fn (): LoginView => new class implements LoginView
    {
        public function respond(LoginPrompt $prompt, Request $request): Response
        {
            return response('login-view');
        }
    });
    app()->bind(RegisterView::class, fn (): RegisterView => new class implements RegisterView
    {
        public function respond(Request $request): Response
        {
            return response('register-view');
        }
    });
    app()->bind(PasswordResetRequestView::class, fn (): PasswordResetRequestView => new class implements PasswordResetRequestView
    {
        public function respond(PasswordResetRequestPrompt $prompt, Request $request): Response
        {
            return response('forgot-password-view');
        }
    });
    app()->bind(PasswordResetView::class, fn (): PasswordResetView => new class implements PasswordResetView
    {
        public function respond(PasswordResetPrompt $prompt, Request $request): Response
        {
            return response('reset-password-view:'.$prompt->token);
        }
    });
    app()->bind(EmailVerificationView::class, fn (): EmailVerificationView => new class implements EmailVerificationView
    {
        public function respond(EmailVerificationPrompt $prompt, Request $request): Response
        {
            return response('verify-email-view');
        }
    });
    app()->bind(PasswordConfirmationView::class, fn (): PasswordConfirmationView => new class implements PasswordConfirmationView
    {
        public function respond(Request $request): Response
        {
            return response('confirm-password-view');
        }
    });
    app()->bind(TwoFactorChallengeView::class, fn (): TwoFactorChallengeView => new class implements TwoFactorChallengeView
    {
        public function respond(TwoFactorChallengePrompt $prompt, Request $request): Response
        {
            return response('two-factor-view');
        }
    });

    $this->get('/auth/login')->assertOk()->assertSee('login-view');
    $this->get('/auth/register')->assertOk()->assertSee('register-view');
    $this->get('/auth/forgot-password')->assertOk()->assertSee('forgot-password-view');
    $this->get('/auth/reset-password/reset-token?email=m@example.com')->assertOk()->assertSee('reset-password-view:reset-token');

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')->get('/auth/email/verify')->assertOk()->assertSee('verify-email-view');
    $this->actingAs($user, 'identity')->get('/auth/user/confirm-password')->assertOk()->assertSee('confirm-password-view');

    auth('identity')->logout();
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    $this->withSession(['login.id' => $user->getAuthIdentifier(), 'login.factor' => 'totp'])
        ->get(route('identity.two-factor.login'))
        ->assertOk()
        ->assertSee('two-factor-view');
});
