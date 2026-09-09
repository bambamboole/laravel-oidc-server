<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents;

use Bambamboole\LaravelOidc\Server\Consents\Views\ConsentView;
use Bambamboole\LaravelOidc\Server\Consents\Views\ConsentViewResponse;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\MissingAuthViewException;
use Bambamboole\LaravelOidc\Server\Shared\Consents\AuthorizationViewResponse;
use Illuminate\Support\ServiceProvider;

class ConsentsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(AuthorizationViewResponse::class, ConsentViewResponse::class);
        $this->app->bind(ConsentView::class, fn (): never => throw MissingAuthViewException::forContract(ConsentView::class));
    }
}
