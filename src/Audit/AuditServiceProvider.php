<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

use Bambamboole\LaravelOidc\Server\Audit\Listeners\RecordAuditEvent;
use Bambamboole\LaravelOidc\Server\Audit\Sinks\LogAuditSink;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditSink;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

class AuditServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(AuditSink::class, fn (Application $app): AuditSink => $app->make(
            (string) config('oidc.audit.sink', LogAuditSink::class),
        ));
    }

    public function boot(): void
    {
        Event::listen(AuditEvent::class, RecordAuditEvent::class);
    }
}
