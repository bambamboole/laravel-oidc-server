<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeGrant;
use Workbench\App\Models\User;

it('drops unknown scopes and keeps known ones', function (): void {
    config(['oidc.scopes' => ['project:update' => 'Update projects']]);
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

it('adds the client default scopes for the grants no earlier artifact bounds', function (string $grantType): void {
    config(['oidc.scopes' => ['orders:read' => 'Read orders']]);
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    $client->forceFill(['default_scopes' => ['orders:read']])->save();

    expect(app(ScopeGrant::class)->finalize(['openid'], $grantType, $client))->toBe(['openid', 'orders:read']);
})->with(['client_credentials', 'personal_access']);

it('does not add default scopes for grants bounded by an earlier artifact', function (string $grantType): void {
    config(['oidc.scopes' => ['orders:read' => 'Read orders']]);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Test', ['https://rp.test/callback']);
    $client->forceFill(['default_scopes' => ['orders:read']])->save();

    expect(app(ScopeGrant::class)->finalize(['openid'], $grantType, $client, '1'))->toBe(['openid']);
})->with(['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:token-exchange']);

it('drops a known scope the client is not assigned', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Test', ['https://rp.test/callback']);
    $client->forceFill(['optional_scopes' => ['openid']])->save();

    expect(app(ScopeGrant::class)->finalize(['openid', 'email'], 'authorization_code', $client, '1'))->toBe(['openid']);
});

it('keeps the wildcard only while the client may request every scope', function (): void {
    $client = app(ClientRepository::class)->createPersonalAccessGrantClient('PAT');
    $client->forceFill(['optional_scopes' => ['openid']])->save();

    expect(app(ScopeGrant::class)->finalize(['*', 'openid'], 'personal_access', $client, '1'))->toBe(['openid']);
});
