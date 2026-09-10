<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Testing;

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
use Bambamboole\LaravelOidc\Server\Consents\Views\ConsentPrompt;
use Bambamboole\LaravelOidc\Server\Consents\Views\ConsentView;
use Bambamboole\LaravelOidc\Server\Credentials\Views\TwoFactorChallengePrompt;
use Bambamboole\LaravelOidc\Server\Credentials\Views\TwoFactorChallengeView;
use Bambamboole\LaravelOidc\Server\Sessions\Views\LogoutConfirmationView;
use Bambamboole\LaravelOidc\Server\Sessions\Views\LogoutPrompt;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Binds every auth view contract to a minimal JSON responder so engine tests
 * can drive the real controllers without depending on `bambamboole/laravel-oidc-ui`
 * (or any other view package) being installed. Add to your Pest suite with
 * `uses(FakesAuthViews::class)` (or `use` it in a PHPUnit TestCase), then call
 * `fakeAuthViews()` before hitting a GET route for one of the views.
 */
trait FakesAuthViews
{
    protected function fakeAuthViews(): static
    {
        app()->bind(LoginView::class, fn (): LoginView => new class implements LoginView
        {
            public function respond(LoginPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'login', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(RegisterView::class, fn (): RegisterView => new class implements RegisterView
        {
            public function respond(Request $request): JsonResponse
            {
                return response()->json(['view' => 'register']);
            }
        });

        app()->bind(PasswordResetRequestView::class, fn (): PasswordResetRequestView => new class implements PasswordResetRequestView
        {
            public function respond(PasswordResetRequestPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'request-password-reset-link', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(PasswordResetView::class, fn (): PasswordResetView => new class implements PasswordResetView
        {
            public function respond(PasswordResetPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'reset-password', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(EmailVerificationView::class, fn (): EmailVerificationView => new class implements EmailVerificationView
        {
            public function respond(EmailVerificationPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'verify-email', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(PasswordConfirmationView::class, fn (): PasswordConfirmationView => new class implements PasswordConfirmationView
        {
            public function respond(Request $request): JsonResponse
            {
                return response()->json(['view' => 'confirm-password']);
            }
        });

        app()->bind(TwoFactorChallengeView::class, fn (): TwoFactorChallengeView => new class implements TwoFactorChallengeView
        {
            public function respond(TwoFactorChallengePrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'two-factor-challenge', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(ConsentView::class, fn (): ConsentView => new class implements ConsentView
        {
            public function respond(ConsentPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'consent', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(LogoutConfirmationView::class, fn (): LogoutConfirmationView => new class implements LogoutConfirmationView
        {
            public function respond(LogoutPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'logout-confirmation', 'prompt' => get_object_vars($prompt)]);
            }
        });

        return $this;
    }
}
