<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\LogSink;
use Illuminate\Support\Facades\Log;
use Psr\Log\LoggerInterface;

/**
 * @param  array<string, mixed>  $context
 */
function auditEvent(AuditEventType $type, array $context = []): AuditEvent
{
    return new AuditEvent(
        type: $type,
        userId: '42',
        clientId: null,
        sid: null,
        ip: '10.0.0.1',
        userAgent: null,
        occurredAt: new DateTimeImmutable('2026-08-13T12:00:00+00:00'),
        context: $context,
    );
}

it('logs failure events as warnings on the default channel', function () {
    $logger = Mockery::mock(LoggerInterface::class);
    $logger->expects('log')->withArgs(
        fn (string $level, string $message, array $context): bool => $level === 'warning'
            && $message === 'oidc: audit auth.login.failed'
            && $context['reason'] === 'invalid_credentials'
            && $context['user_id'] === '42'
            && $context['ip'] === '10.0.0.1'
            && $context['occurred_at'] === '2026-08-13T12:00:00+00:00'
            && ! array_key_exists('client_id', $context),
    );
    Log::shouldReceive('channel')->once()->with(null)->andReturn($logger);

    (new LogSink)->record(auditEvent(AuditEventType::LoginFailed, ['reason' => 'invalid_credentials']));
});

it('logs success events as info on the configured channel', function () {
    config()->set('oidc.audit.log_channel', 'audit');

    $logger = Mockery::mock(LoggerInterface::class);
    $logger->expects('log')->withArgs(
        fn (string $level, string $message): bool => $level === 'info'
            && $message === 'oidc: audit oauth.token.issued',
    );
    Log::shouldReceive('channel')->once()->with('audit')->andReturn($logger);

    (new LogSink)->record(auditEvent(AuditEventType::TokenIssued));
});

it('derives the category from the type value', function () {
    expect(AuditEventType::LoginFailed->category())->toBe('auth')
        ->and(AuditEventType::TokenIssued->category())->toBe('oauth')
        ->and(AuditEventType::KeysRotated->category())->toBe('admin');
});
