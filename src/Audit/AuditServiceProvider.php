<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditSink;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class AuditServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(AuditSink::class, fn (Application $app): AuditSink => $app->make(
            (string) config('oidc.audit.sink', LogSink::class),
        ));
        $this->app->singleton(Auditor::class, DefaultAuditor::class);
    }
}
