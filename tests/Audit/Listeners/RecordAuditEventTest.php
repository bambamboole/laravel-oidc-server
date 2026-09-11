<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Events\LoggedOut;
use Bambamboole\LaravelOidc\Server\Authentication\Events\LoginFailed;
use Bambamboole\LaravelOidc\Server\Authentication\Events\LoginSucceeded;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditSink;
use Bambamboole\LaravelOidc\Server\Tokens\Events\TokenIssued;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Exceptions;

enum HostAuditType: string
{
    case ExportDownloaded = 'app.export.downloaded';
}

it('records a dispatched audit event through the configured sink', function (): void {
    $sink = fakeAudit();

    event(new LoginSucceeded('42', ['pwd']));

    $record = $sink->assertRecorded(AuditEventType::LoginSucceeded);

    expect($record->userId)->toBe('42')
        ->and($record->context)->toBe(['amr' => ['pwd']])
        ->and($record->failure)->toBeFalse()
        ->and($record->category())->toBe('auth');
});

it('records any event implementing the audit contract, including host-defined ones', function (): void {
    $sink = fakeAudit();

    event(new class implements AuditEvent
    {
        public string|BackedEnum $type { get => 'app.export.downloaded'; }

        public function auditRecord(): AuditRecord
        {
            return new AuditRecord($this->type, userId: '7', context: ['file' => 'report.csv']);
        }
    });

    expect($sink->assertRecorded('app.export.downloaded')->context)->toBe(['file' => 'report.csv']);
});

it('stores a backed enum type as its value', function (): void {
    $sink = fakeAudit();

    event(new class implements AuditEvent
    {
        public string|BackedEnum $type { get => HostAuditType::ExportDownloaded; }

        public function auditRecord(): AuditRecord
        {
            return new AuditRecord($this->type, userId: '7');
        }
    });

    $record = $sink->assertRecorded(HostAuditType::ExportDownloaded);

    expect($record->type)->toBe('app.export.downloaded')
        ->and($record->category())->toBe('app');
});

it('stops recording when audit logging is disabled', function (): void {
    config()->set('oidc.audit.enabled', false);
    $sink = fakeAudit();

    event(new LoginSucceeded('42', ['pwd']));

    $sink->assertNothingRecorded();
});

it('enriches records with request ip and truncated user agent', function (): void {
    $sink = fakeAudit();
    app()->instance('request', Request::create(
        '/login', 'POST', [], [], [],
        ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_USER_AGENT' => str_repeat('a', 300)],
    ));

    event(new LoginFailed('pwd', 'invalid_credentials'));

    $record = $sink->assertRecorded(AuditEventType::LoginFailed);

    expect($record->ip)->toBe('10.0.0.1')
        ->and($record->userAgent)->toBe(str_repeat('a', 255))
        ->and($record->failure)->toBeTrue();
});

it('falls back to the session sid unless the event carries one', function (): void {
    $sink = fakeAudit();
    $this->session(['oidc.sid' => 'sid-123']);

    event(new LoggedOut('42'));
    event(new TokenIssued('refresh_token', 'jti-1', [], sid: 'sid-456'));

    expect($sink->assertRecorded(AuditEventType::LoggedOut)->sid)->toBe('sid-123')
        ->and($sink->assertRecorded(AuditEventType::TokenIssued)->sid)->toBe('sid-456');
});

it('reports and swallows sink failures', function (): void {
    Exceptions::fake();
    app()->instance(AuditSink::class, new class implements AuditSink
    {
        public function record(AuditRecord $record): void
        {
            throw new RuntimeException('sink down');
        }
    });

    event(new LoginSucceeded('42', ['pwd']));

    Exceptions::assertReported(RuntimeException::class);
});
