<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication;

use Bambamboole\LaravelOidc\Server\Authentication\Context\AuthenticationContextStore;
use Bambamboole\LaravelOidc\Server\Authentication\Context\PruneAuthenticationContextsCommand;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\Contracts\DeviceRecognizer;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\NullDeviceRecognizer;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Server\Authentication\Views\EmailVerificationView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\LoginView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\MissingAuthViewException;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordConfirmationView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordResetRequestView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordResetView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\RegisterView;
use Bambamboole\LaravelOidc\Server\Protocol\Controllers\AuthorizationController;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class AuthenticationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $identityGuard = (string) config('oidc.auth.guard', 'identity');

        if (! config()->has("auth.guards.{$identityGuard}")) {
            config()->set("auth.guards.{$identityGuard}", [
                'driver' => 'session',
                'provider' => (string) config('oidc.auth.provider', 'users'),
            ]);
        }

        $this->app->singleton(AccessTokenPipeline::class);
        $this->app->singleton(PostLoginPipeline::class);
        $this->app->singleton(DeviceRecognizer::class, NullDeviceRecognizer::class);
        $this->app->singleton(AuthenticationContextStore::class);

        // Without a ui package or app binding, a view contract throws so the
        // missing page is caught at development time instead of rendering nothing.
        foreach ([
            LoginView::class,
            RegisterView::class,
            PasswordResetRequestView::class,
            PasswordResetView::class,
            EmailVerificationView::class,
            PasswordConfirmationView::class,
        ] as $contract) {
            $this->app->bind($contract, fn (): never => throw MissingAuthViewException::forContract($contract));
        }

        $this->app->when(AuthorizationController::class)
            ->needs(StatefulGuard::class)
            ->give(fn () => Auth::guard((string) config('oidc.auth.guard', 'identity')));
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([PruneAuthenticationContextsCommand::class]);
        }

        ResetPassword::createUrlUsing(fn (mixed $notifiable, string $token): string => url(route(
            'identity.password.reset',
            ['token' => $token, 'email' => $notifiable->getEmailForPasswordReset()],
            false,
        )));
        VerifyEmail::createUrlUsing(fn (mixed $notifiable): string => URL::temporarySignedRoute(
            'identity.verification.verify',
            Carbon::now()->addMinutes((int) config('auth.verification.expire', 60)),
            ['id' => $notifiable->getKey(), 'hash' => sha1($notifiable->getEmailForVerification())],
        ));
    }
}
