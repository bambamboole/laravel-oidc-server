<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents;

use Bambamboole\LaravelOidc\Server\Authentication\Views\MissingAuthViewException;
use Bambamboole\LaravelOidc\Server\Consents\Views\AuthorizationViewResponse;
use Bambamboole\LaravelOidc\Server\Consents\Views\ConsentView;
use Bambamboole\LaravelOidc\Server\Consents\Views\ConsentViewResponse;
use Illuminate\Support\ServiceProvider;

class ConsentsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(AuthorizationViewResponse::class, ConsentViewResponse::class);
        $this->app->bind(ConsentView::class, fn (): never => throw MissingAuthViewException::forContract(ConsentView::class));
    }
}
