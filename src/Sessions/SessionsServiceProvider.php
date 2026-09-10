<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions;

use Bambamboole\LaravelOidc\Server\Sessions\BackChannel\BackChannelLogoutNotifier;
use Bambamboole\LaravelOidc\Server\Sessions\Commands\DispatchExpiredSessionLogoutsCommand;
use Bambamboole\LaravelOidc\Server\Sessions\Commands\PruneSessionsCommand;
use Bambamboole\LaravelOidc\Server\Sessions\Listeners\EndOidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\Listeners\EstablishSessionToken;
use Bambamboole\LaravelOidc\Server\Sessions\Listeners\ForgetSessionToken;
use Bambamboole\LaravelOidc\Server\Sessions\Listeners\StartOidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\Views\LogoutConfirmationView;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\MissingAuthViewException;
use Bambamboole\LaravelOidc\Server\Shared\Sessions\SessionTokenProvider;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

class SessionsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(SessionTokenProvider::class, SessionTokenIssuer::class);
        $this->app->singleton(OidcSessionRepository::class);
        $this->app->singleton(BackChannelLogoutNotifier::class);
        $this->app->bind(LogoutConfirmationView::class, fn (): never => throw MissingAuthViewException::forContract(LogoutConfirmationView::class));
    }

    public function boot(): void
    {
        Event::listen(Login::class, EstablishSessionToken::class);
        Event::listen(Login::class, StartOidcSession::class);
        Event::listen(Logout::class, ForgetSessionToken::class);
        Event::listen(Logout::class, EndOidcSession::class);

        if ($this->app->runningInConsole()) {
            $this->commands([DispatchExpiredSessionLogoutsCommand::class, PruneSessionsCommand::class]);
        }
    }
}
