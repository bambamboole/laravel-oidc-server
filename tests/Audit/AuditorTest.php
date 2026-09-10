<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditSink;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;

it('records events through the configured sink and dispatches them to listeners', function (): void {
    $sink = fakeAudit();
    Event::fake([AuditEvent::class]);

    app(Auditor::class)->log(AuditEventType::LoginSucceeded, userId: '42', clientId: 'client-1', context: ['method' => 'pwd']);

    $event = $sink->assertRecorded(AuditEventType::LoginSucceeded);

    expect($event->userId)->toBe('42')
        ->and($event->context)->toBe(['method' => 'pwd']);

    Event::assertDispatched(AuditEvent::class, fn (AuditEvent $event): bool => $event->type === AuditEventType::LoginSucceeded && $event->clientId === 'client-1');
});

it('short-circuits when audit logging is disabled', function (): void {
    config()->set('oidc.audit.enabled', false);
    $sink = fakeAudit();
    Event::fake([AuditEvent::class]);

    app(Auditor::class)->log(AuditEventType::LoginSucceeded);

    $sink->assertNothingRecorded();
    Event::assertNotDispatched(AuditEvent::class);
});

it('enriches events with request ip and truncated user agent', function (): void {
    $sink = fakeAudit();
    app()->instance('request', Request::create(
        '/login', 'POST', [], [], [],
        ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_USER_AGENT' => str_repeat('a', 300)],
    ));

    app(Auditor::class)->log(AuditEventType::LoginFailed);

    $event = $sink->assertRecorded(AuditEventType::LoginFailed);

    expect($event->ip)->toBe('10.0.0.1')
        ->and($event->userAgent)->toBe(str_repeat('a', 255));
});

it('falls back to the session sid unless one is passed explicitly', function (): void {
    $sink = fakeAudit();
    $this->session(['oidc.sid' => 'sid-123']);

    app(Auditor::class)->log(AuditEventType::Logout);
    app(Auditor::class)->log(AuditEventType::TokenIssued, sid: 'sid-456');

    expect($sink->assertRecorded(AuditEventType::Logout)->sid)->toBe('sid-123')
        ->and($sink->assertRecorded(AuditEventType::TokenIssued)->sid)->toBe('sid-456');
});

it('reports and swallows sink failures', function (): void {
    Exceptions::fake();
    app()->instance(AuditSink::class, new class implements AuditSink
    {
        public function record(AuditEvent $event): void
        {
            throw new RuntimeException('sink down');
        }
    });

    app(Auditor::class)->log(AuditEventType::LoginSucceeded);

    Exceptions::assertReported(RuntimeException::class);
});
