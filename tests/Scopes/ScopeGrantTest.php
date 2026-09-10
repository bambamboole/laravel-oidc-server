<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeGrant;
use Workbench\App\Models\User;

it('drops unknown scopes and keeps known ones', function (): void {
    config(['oidc.scopes.catalog' => ['project:update' => 'Update projects']]);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Test', ['https://rp.test/callback']);

    expect(app(ScopeGrant::class)->finalize(['openid', 'project:update', 'nope'], 'authorization_code', $client, '1'))
        ->toBe(['openid', 'project:update']);
});

it('keeps the wildcard scope for exempt grant types', function (): void {
    $client = app(ClientRepository::class)->createPersonalAccessGrantClient('PAT');

    expect(app(ScopeGrant::class)->finalize(['*'], 'personal_access', $client, '1'))->toBe(['*']);
});

it('rejects the wildcard scope for authorization_code finalization', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Test', ['https://rp.test/callback']);

    expect(app(ScopeGrant::class)->finalize(['openid', '*'], 'authorization_code', $client, '1'))->toBe(['openid']);
});

it('issues a personal access token with the wildcard scope', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    app(ClientRepository::class)->createPersonalAccessGrantClient('PAT');

    expect($user->createToken('wildcard', ['*'])->token->getAttribute('scopes'))->toBe(['*']);
});
