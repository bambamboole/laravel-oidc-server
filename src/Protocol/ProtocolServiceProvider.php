<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol;

use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PendingAuthorization;
use Bambamboole\LaravelOidc\Server\Protocol\Authorize\CompleteAuthorizeRequest;
use Bambamboole\LaravelOidc\Server\Protocol\Authorize\PendingAuthorizationRequest;
use Bambamboole\LaravelOidc\Server\Protocol\Clients\ClientAuthenticator;
use Bambamboole\LaravelOidc\Server\Protocol\Controllers\AuthorizationController;
use Bambamboole\LaravelOidc\Server\Protocol\Grants\AuthorizationCodeGrant;
use Bambamboole\LaravelOidc\Server\Protocol\Grants\ClientCredentialsGrant;
use Bambamboole\LaravelOidc\Server\Protocol\Grants\RefreshTokenGrant;
use Bambamboole\LaravelOidc\Server\Protocol\Grants\TokenExchangeGrant;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\AuthorizationCompleter;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class ProtocolServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(PendingAuthorization::class, PendingAuthorizationRequest::class);
        $this->app->bind(AuthorizationCompleter::class, CompleteAuthorizeRequest::class);

        $this->app->when(AuthorizationController::class)
            ->needs(StatefulGuard::class)
            ->give(fn () => Auth::guard((string) config('oidc.auth.guard', 'identity')));

        // Built per request: the grants on offer follow the current realm's settings.
        $this->app->bind(TokenEndpoint::class, function (Application $app): TokenEndpoint {
            $grants = [
                $app->make(AuthorizationCodeGrant::class),
                $app->make(RefreshTokenGrant::class),
                $app->make(ClientCredentialsGrant::class),
            ];

            if ($app->make(RealmResolver::class)->current()->clients()->tokenExchange) {
                $grants[] = $app->make(TokenExchangeGrant::class);
            }

            return new TokenEndpoint($app->make(ClientAuthenticator::class), $grants);
        });
    }
}
