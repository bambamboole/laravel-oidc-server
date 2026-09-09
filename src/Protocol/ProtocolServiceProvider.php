<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol;

use Bambamboole\LaravelOidc\Server\Protocol\League\AuthorizationServerFactory;
use Bambamboole\LaravelOidc\Server\Protocol\League\Repositories\AccessTokenRepository;
use Bambamboole\LaravelOidc\Server\Protocol\League\Repositories\AuthCodeRepository;
use Bambamboole\LaravelOidc\Server\Protocol\League\Repositories\ClientRepository;
use Bambamboole\LaravelOidc\Server\Protocol\League\Repositories\RefreshTokenRepository;
use Bambamboole\LaravelOidc\Server\Protocol\League\Repositories\UserRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;

class ProtocolServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(AccessTokenRepositoryInterface::class, AccessTokenRepository::class);
        $this->app->bind(ClientRepositoryInterface::class, ClientRepository::class);
        $this->app->bind(RefreshTokenRepositoryInterface::class, RefreshTokenRepository::class);
        $this->app->bind(AuthCodeRepositoryInterface::class, AuthCodeRepository::class);
        $this->app->bind(UserRepositoryInterface::class, UserRepository::class);

        $this->app->scoped(AuthorizationServer::class, fn (Application $app): AuthorizationServer => $app
            ->make(AuthorizationServerFactory::class)
            ->make());
    }
}
