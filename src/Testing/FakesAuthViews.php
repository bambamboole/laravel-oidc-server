<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Testing;

use Bambamboole\LaravelOidc\Auth\Views\ConsentPrompt;
use Bambamboole\LaravelOidc\Auth\Views\ConsentView;
use Bambamboole\LaravelOidc\Auth\Views\EmailVerificationPrompt;
use Bambamboole\LaravelOidc\Auth\Views\EmailVerificationView;
use Bambamboole\LaravelOidc\Auth\Views\LoginPrompt;
use Bambamboole\LaravelOidc\Auth\Views\LoginView;
use Bambamboole\LaravelOidc\Auth\Views\PasswordConfirmationPrompt;
use Bambamboole\LaravelOidc\Auth\Views\PasswordConfirmationView;
use Bambamboole\LaravelOidc\Auth\Views\PasswordResetPrompt;
use Bambamboole\LaravelOidc\Auth\Views\PasswordResetRequestPrompt;
use Bambamboole\LaravelOidc\Auth\Views\PasswordResetRequestView;
use Bambamboole\LaravelOidc\Auth\Views\PasswordResetView;
use Bambamboole\LaravelOidc\Auth\Views\RegisterPrompt;
use Bambamboole\LaravelOidc\Auth\Views\RegisterView;
use Bambamboole\LaravelOidc\Auth\Views\TwoFactorChallengePrompt;
use Bambamboole\LaravelOidc\Auth\Views\TwoFactorChallengeView;
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
        app()->bind(LoginView::class, fn () => new class implements LoginView
        {
            public function respond(LoginPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'login', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(RegisterView::class, fn () => new class implements RegisterView
        {
            public function respond(RegisterPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'register', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(PasswordResetRequestView::class, fn () => new class implements PasswordResetRequestView
        {
            public function respond(PasswordResetRequestPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'request-password-reset-link', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(PasswordResetView::class, fn () => new class implements PasswordResetView
        {
            public function respond(PasswordResetPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'reset-password', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(EmailVerificationView::class, fn () => new class implements EmailVerificationView
        {
            public function respond(EmailVerificationPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'verify-email', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(PasswordConfirmationView::class, fn () => new class implements PasswordConfirmationView
        {
            public function respond(PasswordConfirmationPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'confirm-password', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(TwoFactorChallengeView::class, fn () => new class implements TwoFactorChallengeView
        {
            public function respond(TwoFactorChallengePrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'two-factor-challenge', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(ConsentView::class, fn () => new class implements ConsentView
        {
            public function respond(ConsentPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'consent', 'prompt' => get_object_vars($prompt)]);
            }
        });

        return $this;
    }
}
