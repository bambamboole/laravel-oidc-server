<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

use Bambamboole\LaravelOidc\Server\Auth\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Contracts\AuditSink;
use DateTimeImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Throwable;

/**
 * Singleton: request and session state are resolved per call, never captured,
 * so the instance stays safe under Octane. Recording is fail-open — a broken
 * sink or listener must never take down an auth or token flow, so failures
 * are reported and swallowed.
 */
final class Auditor
{
    public function __construct(private readonly Container $app) {}

    /**
     * @param  array<string, mixed>  $context
     */
    public function log(
        AuditEventType $type,
        ?string $userId = null,
        ?string $clientId = null,
        ?string $sid = null,
        array $context = [],
    ): void {
        if (! config('oidc.audit.enabled', true)) {
            return;
        }

        $request = $this->request();

        $event = new AuditEvent(
            type: $type,
            userId: $userId,
            clientId: $clientId,
            sid: $sid ?? $this->sessionSid(),
            ip: $request?->ip(),
            userAgent: $this->userAgent($request),
            occurredAt: new DateTimeImmutable,
            context: $context,
        );

        try {
            $this->app->make(Dispatcher::class)->dispatch($event);
            $this->app->make(AuditSink::class)->record($event);
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
