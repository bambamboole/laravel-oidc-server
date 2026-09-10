<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit\Listeners;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditSink;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AuthSessionState;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Throwable;

/**
 * Request and session state are resolved per event, never captured, so the
 * listener stays safe under Octane. Recording is fail-open: a broken sink
 * must never take down the auth or token flow that raised the event, so
 * failures are reported and swallowed.
 */
final readonly class RecordAuditEvent
{
    public function __construct(private Container $app) {}

    public function handle(AuditEvent $event): void
    {
        if (! config('oidc.audit.enabled', true)) {
            return;
        }

        try {
            $request = $this->request();

            $this->app->make(AuditSink::class)->record($event->auditRecord()->withRequestContext(
                ip: $request?->ip(),
                userAgent: $this->userAgent($request),
                sid: $this->sessionSid(),
            ));
        } catch (Throwable $exception) {
            report($exception);
        }
    }

    private function request(): ?Request
    {
        return $this->app->bound('request') ? $this->app->make('request') : null;
    }

    private function userAgent(?Request $request): ?string
    {
        $userAgent = $request?->userAgent();

        return is_string($userAgent) && $userAgent !== ''
            ? mb_substr($userAgent, 0, 255)
            : null;
    }

    private function sessionSid(): ?string
    {
        if (! $this->app->bound('session.store') || ! $this->app->make('session.store')->isStarted()) {
            return null;
        }

        return $this->app->make(AuthSessionState::class)->sid();
    }
}
