<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Audit;

use Bambamboole\LaravelOidc\Server\Contracts\AuditSink;
use DateTimeInterface;
use Illuminate\Support\Facades\Log;

final class LogSink implements AuditSink
{
    public function record(AuditEvent $event): void
    {
        $channel = config('oidc.audit.log_channel');

        Log::channel(is_string($channel) && $channel !== '' ? $channel : null)->log(
            $event->type->isFailure() ? 'warning' : 'info',
            'oidc: audit '.$event->type->value,
            [
                ...array_filter([
                    'user_id' => $event->userId,
                    'client_id' => $event->clientId,
                    'sid' => $event->sid,
                    'ip' => $event->ip,
                    'user_agent' => $event->userAgent,
                ], static fn (?string $value): bool => $value !== null),
                'occurred_at' => $event->occurredAt->format(DateTimeInterface::ATOM),
                ...$event->context,
            ],
        );
    }
}
