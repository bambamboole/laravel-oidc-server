<?php

declare(strict_types=1);

/**
 * RFC 9068 §2.2, §4 (aud); RFC 9728 §3.3 (protected resource identifiers)
 */

use Bambamboole\LaravelOidc\Server\Shared\Tokens\RealmAudiences;

beforeEach(function (): void {
    config(['app.url' => 'https://op.test', 'oidc.issuer' => null]);
});

it('defaults to the realm issuer url', function (): void {
    expect(app(RealmAudiences::class)->all())->toBe(['https://op.test']);
});

it('replaces the issuer with the configured audiences', function (): void {
    config(['oidc.tokens.audiences' => ['https://api.example/orders', 'https://api.example/billing']]);

    expect(app(RealmAudiences::class)->all())->toBe(['https://api.example/orders', 'https://api.example/billing']);
});

it('adds every advertised protected resource, without duplicates', function (): void {
    config(['oidc.protected_resources' => ['mcp' => ['scopes' => []], '' => ['scopes' => []]]]);

    $audiences = app(RealmAudiences::class);

    expect($audiences->all())->toBe(['https://op.test', 'https://op.test/mcp'])
        ->and($audiences->protectedResource('mcp'))->toBe('https://op.test/mcp')
        ->and($audiences->protectedResource(''))->toBe('https://op.test');
});

it('accepts an audience naming one of them and rejects any other', function (): void {
    config(['oidc.tokens.audiences' => ['https://api.example/orders']]);

    $audiences = app(RealmAudiences::class);

    expect($audiences->accepts(['https://api.example/orders', 'https://elsewhere.example']))->toBeTrue()
        ->and($audiences->accepts(['https://op.test']))->toBeFalse()
        ->and($audiences->accepts(['some-client-id']))->toBeFalse()
        ->and($audiences->accepts([]))->toBeFalse();
});
