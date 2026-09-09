<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication;

use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\Contracts\DeviceRecognizer;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\NullDeviceRecognizer;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Server\Http\Controllers\AuthorizationController;
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

        $this->app->when(AuthorizationController::class)
            ->needs(StatefulGuard::class)
            ->give(fn () => Auth::guard((string) config('oidc.auth.guard', 'identity')));
    }

    public function boot(): void
    {
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
