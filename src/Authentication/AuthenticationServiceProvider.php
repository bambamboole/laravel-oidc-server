<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication;

use Bambamboole\LaravelOidc\Server\Authentication\Actions\ResetPassword as ResetPasswordAction;
use Bambamboole\LaravelOidc\Server\Authentication\Actions\SendPasswordResetLink;
use Bambamboole\LaravelOidc\Server\Authentication\Commands\PruneAuthenticationContextsCommand;
use Bambamboole\LaravelOidc\Server\Authentication\Context\AuthenticationContextStore;
use Bambamboole\LaravelOidc\Server\Authentication\Listeners\DispatchLoggedOut;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\InteractiveLoginFinalizer;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\NullDeviceRecognizer;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Server\Authentication\RequiredActions\DerivedPendingActions;
use Bambamboole\LaravelOidc\Server\Authentication\Views\EmailVerificationView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\LoginView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordConfirmationView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordResetRequestView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordResetView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\PasswordUpdateView;
use Bambamboole\LaravelOidc\Server\Authentication\Views\RegisterView;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AcrResolver;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\DeviceRecognizer;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\LoginFinalizer;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\MissingAuthViewException;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\PendingActions;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\PasswordBroker as PasswordBrokerContract;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
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

        $this->app->singleton(PostLoginPipeline::class);
        $this->app->singleton(LoginFinalizer::class, InteractiveLoginFinalizer::class);
        $this->app->singleton(DeviceRecognizer::class, NullDeviceRecognizer::class);
        $this->app->bind(AcrResolver::class, LevelOfAssuranceAcrResolver::class);
        $this->app->singleton(AuthenticationContextStore::class);
        $this->app->when([SendPasswordResetLink::class, ResetPasswordAction::class])
            ->needs(PasswordBrokerContract::class)
            ->give(fn (Application $app): PasswordBroker => new PasswordBroker(
                $app->make(PasswordResetTokens::class),
                $app->make(AuthFactory::class)->createUserProvider((string) config('oidc.auth.provider', 'users')),
                $app->make(Dispatcher::class),
            ));
        $this->app->singleton(PendingActions::class, DerivedPendingActions::class);

        // Without a ui package or app binding, a view contract throws so the
        // missing page is caught at development time instead of rendering nothing.
        foreach ([
            LoginView::class,
            RegisterView::class,
            PasswordResetRequestView::class,
            PasswordResetView::class,
            EmailVerificationView::class,
            PasswordConfirmationView::class,
            PasswordUpdateView::class,
        ] as $contract) {
            $this->app->bind($contract, fn (): never => throw MissingAuthViewException::forContract($contract));
        }
    }

    public function boot(): void
    {
        Event::listen(Logout::class, DispatchLoggedOut::class);

        if ($this->app->runningInConsole()) {
            $this->commands([PruneAuthenticationContextsCommand::class]);
        }

        ResetPassword::createUrlUsing(fn (mixed $notifiable, string $token): string => route(
            'identity.password.reset',
            ['token' => $token, 'email' => $notifiable->getEmailForPasswordReset()],
        ));
        VerifyEmail::createUrlUsing(fn (mixed $notifiable): string => URL::temporarySignedRoute(
            'identity.verification.verify',
            Carbon::now()->addMinutes((int) config('auth.verification.expire', 60)),
            ['id' => $notifiable->getKey(), 'hash' => sha1($notifiable->getEmailForVerification())],
        ));
    }
}
