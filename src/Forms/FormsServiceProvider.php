<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Forms;

use Illuminate\Support\ServiceProvider;

class FormsServiceProvider extends ServiceProvider
{
    /**
     * Every auth surface resolves through the container: without a ui
     * package or app binding, the default throws so the missing view is
     * caught at development time instead of rendering nothing.
     */
    public function register(): void
    {
        $this->app->bind(AuthorizationViewResponse::class, ConsentViewResponse::class);

        foreach ([
            LoginView::class,
            RegisterView::class,
            PasswordResetRequestView::class,
            PasswordResetView::class,
            EmailVerificationView::class,
            PasswordConfirmationView::class,
            TwoFactorChallengeView::class,
            ConsentView::class,
        ] as $contract) {
            $this->app->bind($contract, fn (): never => throw MissingAuthViewException::forContract($contract));
        }
    }
}
