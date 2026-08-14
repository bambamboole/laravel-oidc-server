<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Audit\AuditEvent;
use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioner;
use Bambamboole\LaravelOidc\Server\Routing\HandlerRegistrar;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Route;

it('audits a dynamic client registration', function () {
    config(['oidc.dcr.enabled' => true]);
    app(HandlerRegistrar::class)->register();
    Route::getRoutes()->refreshNameLookups();
    $sink = fakeAudit();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'MCP Client',
        'redirect_uris' => ['https://mcp.test/callback'],
    ])->assertCreated();

    $sink->assertRecorded(AuditEventType::ClientRegistered, fn (AuditEvent $event): bool => $event->clientId === $response->json('client_id')
        && $event->context['client_name'] === 'MCP Client'
        && $event->context['redirect_uris'] === ['https://mcp.test/callback']);
});

it('audits first party client provisioning and secret rotation', function () {
    $sink = fakeAudit();

    $result = app(FirstPartyClientProvisioner::class)->provision(
        'First-Party App',
        ['https://app.test/callback'],
    );

    $sink->assertRecorded(AuditEventType::ClientProvisioned, fn (AuditEvent $event): bool => $event->clientId === $result->clientId
        && $event->context['created'] === true
        && $event->context['secret_rotated'] === false);

    app(FirstPartyClientProvisioner::class)->provision(
        'First-Party App',
        ['https://app.test/callback'],
        rotateSecret: true,
    );

    $sink->assertRecorded(AuditEventType::ClientProvisioned, fn (AuditEvent $event): bool => $event->context['secret_rotated'] === true
        && $event->context['created'] === false);
});

it('audits a key rotation but not a print run', function () {
    $directory = temporaryTestDirectory('audit-rotate-keys');
    File::put($directory.'/.env', "APP_NAME=Testing\n");
    app()->useEnvironmentPath($directory);

    $sink = fakeAudit();

    $this->artisan('oidc:rotate-keys', ['--print' => true])->assertSuccessful();

    $sink->assertNotRecorded(AuditEventType::KeysRotated);

    $this->artisan('oidc:rotate-keys', ['--force' => true])->assertSuccessful();

    $event = $sink->assertRecorded(AuditEventType::KeysRotated);

    expect($event->context['kid'])->toBeString()
        ->and($event->context)->not->toHaveKeys(['private_key', 'public_key']);
});
