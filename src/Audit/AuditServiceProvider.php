<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

use Bambamboole\LaravelOidc\Server\Audit\Listeners\RecordLoginAudit;
use Bambamboole\LaravelOidc\Server\Audit\Listeners\RecordLogoutAudit;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditSink;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
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
        $this->app->singleton(Auditor::class, SinkAuditor::class);
    }

    public function boot(): void
    {
        // The Sessions provider boots first, so the login audit sees the sid
        // StartOidcSession has already written to the session.
        Event::listen(Login::class, RecordLoginAudit::class);
        Event::listen(Logout::class, RecordLogoutAudit::class);
    }
}
