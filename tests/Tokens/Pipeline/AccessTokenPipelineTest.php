<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AuthorizationCodeEvent;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\ClientCredentialsEvent;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\PersonalAccessTokenEvent;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\TokenExchangeEvent;
use Workbench\App\Models\User;

function pipelineEvent(string $grant): ClientCredentialsEvent|TokenExchangeEvent|PersonalAccessTokenEvent|AuthorizationCodeEvent
{
    $client = (new Client)->forceFill(['client_id' => 'client-id', 'name' => 'Client']);
    $user = new User(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $user->setAttribute($user->getKeyName(), 42);

    return match ($grant) {
        'client_credentials' => new ClientCredentialsEvent(client: $client, scopes: ['orders:read']),
        'token_exchange' => new TokenExchangeEvent(user: $user, client: $client, scopes: ['orders:read'], audience: 'https://api.internal/orders', subjectClaims: ['sub' => 'subject-id']),
        'personal_access_token' => new PersonalAccessTokenEvent(user: $user, client: $client, scopes: ['openid']),
        'authorization_code' => new AuthorizationCodeEvent(user: $user, client: $client, scopes: ['openid', 'email'], grantType: 'refresh_token'),
        default => throw new LogicException('Unknown grant.'),
    };
}

it('runs the triggers of a grant in registration order and stops after an explicit denial', function (string $grant): void {
    $pipeline = new AccessTokenPipeline;
    $order = [];

    $pipeline->register($grant, function (ClientCredentialsEvent|TokenExchangeEvent|PersonalAccessTokenEvent|AuthorizationCodeEvent $event, AccessTokenApi $api) use (&$order): void {
        $order[] = 'first';
        $api->setAccessTokenClaim('granted', $event->scopes);
    });
    $pipeline->register($grant, function (mixed $event, AccessTokenApi $api) use (&$order): void {
        $order[] = 'second';
        $api->deny('blocked');
    });
    $pipeline->register($grant, function () use (&$order): void {
        $order[] = 'third';
    });

    $api = $pipeline->run($grant, pipelineEvent($grant));

    expect($order)->toBe(['first', 'second'])
        ->and($api->accessTokenClaims())->toBe(['granted' => pipelineEvent($grant)->scopes])
        ->and($api->isDenied())->toBeTrue()
        ->and($api->denyReason())->toBe('blocked');
})->with(['client_credentials', 'token_exchange', 'personal_access_token', 'authorization_code']);

it('fails closed with a grant-specific reason and skips later triggers when one throws', function (string $grant): void {
    $pipeline = new AccessTokenPipeline;
    $laterTriggerRan = false;

    $pipeline->register($grant, function (): void {
        throw new RuntimeException('boom');
    });
    $pipeline->register($grant, function () use (&$laterTriggerRan): void {
        $laterTriggerRan = true;
    });

    $api = $pipeline->run($grant, pipelineEvent($grant));

    expect($api->isDenied())->toBeTrue()
        ->and($api->denyReason())->toBe($grant.'_trigger_error')
        ->and($laterTriggerRan)->toBeFalse();
})->with(['client_credentials', 'token_exchange', 'personal_access_token', 'authorization_code']);

it('runs each grant independently with its own event and seeded context', function (): void {
    $pipeline = new AccessTokenPipeline;
    $clientCredentialsTriggerRan = false;

    $pipeline->register('client_credentials', function () use (&$clientCredentialsTriggerRan): void {
        $clientCredentialsTriggerRan = true;
    });
    $pipeline->register('token_exchange', function (TokenExchangeEvent $event, AccessTokenApi $api): void {
        $api->setAccessTokenClaim('exchange', [
            'user' => $event->user->getAuthIdentifier(),
            'audience' => $event->audience,
            'subject' => $event->subjectClaims['sub'],
            'tenant_id' => $api->context('tenant_id'),
        ]);
    });
    $pipeline->register('authorization_code', fn (AuthorizationCodeEvent $event, AccessTokenApi $api) => $api->setAccessTokenClaim('via', $event->grantType));

    $exchange = $pipeline->run('token_exchange', pipelineEvent('token_exchange'), ['tenant_id' => 'acme']);
    $code = $pipeline->run('authorization_code', pipelineEvent('authorization_code'));

    expect($clientCredentialsTriggerRan)->toBeFalse()
        ->and($exchange->accessTokenClaims())->toBe(['exchange' => [
            'user' => 42,
            'audience' => 'https://api.internal/orders',
            'subject' => 'subject-id',
            'tenant_id' => 'acme',
        ]])
        ->and($code->accessTokenClaims())->toBe(['via' => 'refresh_token']);
});

it('returns a fresh access-token api for every invocation', function (): void {
    $pipeline = new AccessTokenPipeline;

    $first = $pipeline->run('client_credentials', pipelineEvent('client_credentials'));
    $first->deny('first_run_only');
    $first->setAccessTokenClaim('first', true);

    $second = $pipeline->run('client_credentials', pipelineEvent('client_credentials'));

    expect($second)->not->toBe($first)
        ->and($second->isDenied())->toBeFalse()
        ->and($second->accessTokenClaims())->toBe([]);
});

it('refuses protected access-token claim :dataset', function (string $claim): void {
    $api = new AccessTokenApi;

    $api->setAccessTokenClaim($claim, 'forged');

    expect($api->accessTokenClaims())->toBe([]);
})->with([
    'iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce', 'at_hash', 'c_hash', 'auth_time', 'azp', 'acr', 'amr', 'sid',
    'client_id', 'scope', 'scopes', 'cnf', 'act',
]);
