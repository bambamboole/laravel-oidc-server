<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Contracts\AuditSink;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;

it('records events through the configured sink', function () {
    $sink = fakeAudit();

    app(Auditor::class)->log(AuditEventType::LoginSucceeded, userId: '42', context: ['method' => 'pwd']);

    $event = $sink->assertRecorded(AuditEventType::LoginSucceeded);

    expect($event->userId)->toBe('42')
        ->and($event->context)->toBe(['method' => 'pwd']);
});

it('dispatches the audit event to listeners', function () {
    fakeAudit();
    Event::fake([AuditEvent::class]);

    app(Auditor::class)->log(AuditEventType::TokenIssued, clientId: 'client-1');

    Event::assertDispatched(
        AuditEvent::class,
        fn (AuditEvent $event): bool => $event->type === AuditEventType::TokenIssued
            && $event->clientId === 'client-1',
    );
});

it('short-circuits when audit logging is disabled', function () {
    config()->set('oidc.audit.enabled', false);
    $sink = fakeAudit();
    Event::fake([AuditEvent::class]);

    app(Auditor::class)->log(AuditEventType::LoginSucceeded);

    $sink->assertNothingRecorded();
    Event::assertNotDispatched(AuditEvent::class);
});

it('enriches events with request ip and truncated user agent', function () {
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

it('falls back to the session sid when none is given', function () {
    $sink = fakeAudit();
    $this->session(['oidc.sid' => 'sid-123']);

    app(Auditor::class)->log(AuditEventType::Logout);

    expect($sink->assertRecorded(AuditEventType::Logout)->sid)->toBe('sid-123');
});

it('prefers an explicitly passed sid over the session sid', function () {
    $sink = fakeAudit();
    $this->session(['oidc.sid' => 'sid-123']);

    app(Auditor::class)->log(AuditEventType::TokenIssued, sid: 'sid-456');

    expect($sink->assertRecorded(AuditEventType::TokenIssued)->sid)->toBe('sid-456');
});

it('reports and swallows sink failures', function () {
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
