<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Auth\Pipeline\AuthorizationCodeEvent;
use Bambamboole\LaravelOidc\Auth\Pipeline\ClientCredentialsEvent;
use Bambamboole\LaravelOidc\Auth\Pipeline\PersonalAccessTokenEvent;
use Bambamboole\LaravelOidc\Auth\Pipeline\TokenExchangeEvent;
use Laravel\Passport\Bridge\Client;
use Workbench\App\Models\User;

function clientCredentialsPipelineEvent(): ClientCredentialsEvent
{
    return new ClientCredentialsEvent(
        client: new Client('client-id', 'Machine client', []),
        scopes: ['orders:read'],
    );
}

function tokenExchangePipelineEvent(): TokenExchangeEvent
{
    $user = new User(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $user->setAttribute($user->getKeyName(), 42);

    return new TokenExchangeEvent(
        user: $user,
        client: new Client('client-id', 'Exchange client', []),
        scopes: ['orders:read'],
        audience: 'https://api.internal/orders',
        subjectClaims: ['sub' => 'subject-id'],
    );
}

it('runs client-credentials triggers in registration order', function () {
    $pipeline = new AccessTokenPipeline;
    $order = [];

    $pipeline->registerClientCredentials(function (ClientCredentialsEvent $event, AccessTokenApi $api) use (&$order): void {
        $order[] = 'first';
        $api->setAccessTokenClaim('scope_count', count($event->scopes));
    });
    $pipeline->registerClientCredentials(function (ClientCredentialsEvent $event, AccessTokenApi $api) use (&$order): void {
        $order[] = 'second';
        $api->setAccessTokenClaim('client', $event->client->getIdentifier());
    });

    $api = $pipeline->runClientCredentials(clientCredentialsPipelineEvent());

    expect($order)->toBe(['first', 'second'])
        ->and($api->accessTokenClaims())->toBe([
            'scope_count' => 1,
            'client' => 'client-id',
        ]);
});

it('stops client-credentials triggers after an explicit denial', function () {
    $pipeline = new AccessTokenPipeline;
    $laterTriggerRan = false;

    $pipeline->registerClientCredentials(function (ClientCredentialsEvent $event, AccessTokenApi $api): void {
        $api->deny('client_blocked');
    });
    $pipeline->registerClientCredentials(function () use (&$laterTriggerRan): void {
        $laterTriggerRan = true;
    });

    $api = $pipeline->runClientCredentials(clientCredentialsPipelineEvent());

    expect($api->isDenied())->toBeTrue()
        ->and($api->denyReason())->toBe('client_blocked')
        ->and($laterTriggerRan)->toBeFalse();
});

it('fails closed and skips later client-credentials triggers when one throws', function () {
    $pipeline = new AccessTokenPipeline;
    $laterTriggerRan = false;

    $pipeline->registerClientCredentials(function (): void {
        throw new RuntimeException('boom');
    });
    $pipeline->registerClientCredentials(function () use (&$laterTriggerRan): void {
        $laterTriggerRan = true;
    });

    $api = $pipeline->runClientCredentials(clientCredentialsPipelineEvent());

    expect($api->isDenied())->toBeTrue()
        ->and($api->denyReason())->toBe('client_credentials_trigger_error')
        ->and($laterTriggerRan)->toBeFalse();
});

it('runs token-exchange triggers independently with their event context', function () {
    $pipeline = new AccessTokenPipeline;
    $clientCredentialsTriggerRan = false;

    $pipeline->registerClientCredentials(function () use (&$clientCredentialsTriggerRan): void {
        $clientCredentialsTriggerRan = true;
    });
    $pipeline->registerTokenExchange(function (TokenExchangeEvent $event, AccessTokenApi $api): void {
        $api->setAccessTokenClaim('exchange', [
            'user' => $event->user->getAuthIdentifier(),
            'audience' => $event->audience,
            'subject' => $event->subjectClaims['sub'],
            'scopes' => $event->scopes,
        ]);
    });

    $api = $pipeline->runTokenExchange(tokenExchangePipelineEvent());

    expect($clientCredentialsTriggerRan)->toBeFalse()
        ->and($api->accessTokenClaims())->toBe([
            'exchange' => [
                'user' => 42,
                'audience' => 'https://api.internal/orders',
                'subject' => 'subject-id',
                'scopes' => ['orders:read'],
            ],
        ]);
});

it('fails closed with a token-exchange-specific reason when a trigger throws', function () {
    $pipeline = new AccessTokenPipeline;

    $pipeline->registerTokenExchange(function (): void {
        throw new RuntimeException('boom');
    });

    $api = $pipeline->runTokenExchange(tokenExchangePipelineEvent());

    expect($api->isDenied())->toBeTrue()
        ->and($api->denyReason())->toBe('token_exchange_trigger_error');
});

it('returns a fresh access-token api for every invocation', function () {
    $pipeline = new AccessTokenPipeline;

    $first = $pipeline->runClientCredentials(clientCredentialsPipelineEvent());
    $first->deny('first_run_only');
    $first->setAccessTokenClaim('first', true);

    $second = $pipeline->runClientCredentials(clientCredentialsPipelineEvent());

    expect($second)->not->toBe($first)
        ->and($second->isDenied())->toBeFalse()
        ->and($second->accessTokenClaims())->toBe([]);
});

function personalAccessPipelineEvent(): PersonalAccessTokenEvent
{
    $user = new User(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $user->setAttribute($user->getKeyName(), 42);

    return new PersonalAccessTokenEvent(
        user: $user,
        client: new Client('client-id', 'PAT client', []),
        scopes: ['openid'],
    );
}

function authorizationCodePipelineEvent(string $grantType = 'authorization_code'): AuthorizationCodeEvent
{
    $user = new User(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $user->setAttribute($user->getKeyName(), 42);

    return new AuthorizationCodeEvent(
        user: $user,
        client: new Client('client-id', 'Interactive client', []),
        scopes: ['openid', 'email'],
        grantType: $grantType,
    );
}

it('runs personal-access triggers in registration order with their event context', function () {
    $pipeline = new AccessTokenPipeline;
    $order = [];

    $pipeline->registerPersonalAccessToken(function (PersonalAccessTokenEvent $event, AccessTokenApi $api) use (&$order): void {
        $order[] = 'first';
        $api->setAccessTokenClaim('user', $event->user->getAuthIdentifier());
    });
    $pipeline->registerPersonalAccessToken(function (PersonalAccessTokenEvent $event, AccessTokenApi $api) use (&$order): void {
        $order[] = 'second';
        $api->setAccessTokenClaim('granted', $event->scopes);
    });

    $api = $pipeline->runPersonalAccessToken(personalAccessPipelineEvent());

    expect($order)->toBe(['first', 'second'])
        ->and($api->accessTokenClaims())->toBe([
            'user' => 42,
            'granted' => ['openid'],
        ]);
});

it('fails closed with a personal-access-specific reason when a trigger throws', function () {
    $pipeline = new AccessTokenPipeline;
    $laterTriggerRan = false;

    $pipeline->registerPersonalAccessToken(function (): void {
        throw new RuntimeException('boom');
    });
    $pipeline->registerPersonalAccessToken(function () use (&$laterTriggerRan): void {
        $laterTriggerRan = true;
    });

    $api = $pipeline->runPersonalAccessToken(personalAccessPipelineEvent());

    expect($api->isDenied())->toBeTrue()
        ->and($api->denyReason())->toBe('personal_access_trigger_error')
        ->and($laterTriggerRan)->toBeFalse();
});

it('reports whether personal-access triggers are registered', function () {
    $pipeline = new AccessTokenPipeline;

    expect($pipeline->hasPersonalAccessTokenTriggers())->toBeFalse();

    $pipeline->registerPersonalAccessToken(function (): void {});

    expect($pipeline->hasPersonalAccessTokenTriggers())->toBeTrue();
});

it('runs authorization-code triggers with the grant type on the event', function () {
    $pipeline = new AccessTokenPipeline;

    $pipeline->registerAuthorizationCode(function (AuthorizationCodeEvent $event, AccessTokenApi $api): void {
        $api->setAccessTokenClaim('via', $event->grantType);
        $api->setAccessTokenClaim('granted', $event->scopes);
    });

    $api = $pipeline->runAuthorizationCode(authorizationCodePipelineEvent('refresh_token'));

    expect($api->accessTokenClaims())->toBe([
        'via' => 'refresh_token',
        'granted' => ['openid', 'email'],
    ]);
});

it('stops authorization-code triggers after an explicit denial', function () {
    $pipeline = new AccessTokenPipeline;
    $laterTriggerRan = false;

    $pipeline->registerAuthorizationCode(function (AuthorizationCodeEvent $event, AccessTokenApi $api): void {
        $api->deny('user_blocked');
    });
    $pipeline->registerAuthorizationCode(function () use (&$laterTriggerRan): void {
        $laterTriggerRan = true;
    });

    $api = $pipeline->runAuthorizationCode(authorizationCodePipelineEvent());

    expect($api->isDenied())->toBeTrue()
        ->and($api->denyReason())->toBe('user_blocked')
        ->and($laterTriggerRan)->toBeFalse();
});

it('fails closed with an authorization-code-specific reason when a trigger throws', function () {
    $pipeline = new AccessTokenPipeline;

    $pipeline->registerAuthorizationCode(function (): void {
        throw new RuntimeException('boom');
    });

    $api = $pipeline->runAuthorizationCode(authorizationCodePipelineEvent());

    expect($api->isDenied())->toBeTrue()
        ->and($api->denyReason())->toBe('authorization_code_trigger_error');
});

it('reports whether authorization-code triggers are registered', function () {
    $pipeline = new AccessTokenPipeline;

    expect($pipeline->hasAuthorizationCodeTriggers())->toBeFalse();

    $pipeline->registerAuthorizationCode(function (): void {});

    expect($pipeline->hasAuthorizationCodeTriggers())->toBeTrue();
});
