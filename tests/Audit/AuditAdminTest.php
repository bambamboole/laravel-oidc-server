<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioner;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditRecord;

it('audits a dynamic client registration', function (): void {
    config(['oidc.clients.registration.enabled' => true]);
    reloadOidcRoutes();
    $sink = fakeAudit();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Agent',
        'redirect_uris' => ['https://mcp.test/callback'],
    ])->assertCreated();

    $sink->assertRecorded(AuditEventType::ClientRegistered, fn (AuditRecord $record): bool => $record->clientId === $response->json('client_id')
        && $record->context['client_name'] === 'Agent'
        && $record->context['redirect_uris'] === ['https://mcp.test/callback']);
});

it('audits first party client provisioning and secret rotation', function (): void {
    $sink = fakeAudit();

    $result = app(FirstPartyClientProvisioner::class)->provision(
        'First-Party App',
        ['https://app.test/callback'],
    );

    $sink->assertRecorded(AuditEventType::ClientProvisioned, fn (AuditRecord $record): bool => $record->clientId === $result->clientId
        && $record->context['created'] === true
        && $record->context['secret_rotated'] === false);

    app(FirstPartyClientProvisioner::class)->provision(
        'First-Party App',
        ['https://app.test/callback'],
        rotateSecret: true,
    );

    $sink->assertRecorded(AuditEventType::ClientProvisioned, fn (AuditRecord $record): bool => $record->context['secret_rotated'] === true
        && $record->context['created'] === false);
});

it('audits a key rotation but not a skipped one', function (): void {
    $sink = fakeAudit();

    $this->artisan('oidc:rotate-keys', ['--if-missing' => true])->assertSuccessful();

    $sink->assertNotRecorded(AuditEventType::KeysRotated);

    $this->artisan('oidc:rotate-keys', ['--force' => true])->assertSuccessful();

    $record = $sink->assertRecorded(AuditEventType::KeysRotated);

    expect($record->context['kid'])->toBeString()
        ->and($record->context)->not->toHaveKeys(['private_key', 'public_key']);
});
