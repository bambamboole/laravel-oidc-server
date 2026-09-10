<?php

declare(strict_types=1);

/**
 * Personal access tokens: RFC 9068 access token minted through the token pipeline for the personal_access grant
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\PersonalAccessTokenEvent;
use Bambamboole\LaravelOidc\Server\Tokens\TokenIssuanceDeniedException;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    app(ClientRepository::class)->createPersonalAccessGrantClient('PAT');
});

it('runs the personal-access trigger once and applies its claims to the issued token', function () {
    $triggerCount = 0;

    app(AccessTokenPipeline::class)->register('personal_access_token', function (PersonalAccessTokenEvent $event, AccessTokenApi $api) use (&$triggerCount): void {
        $triggerCount++;

        expect($event->user->getAuthIdentifier())->toBe($this->user->id)
            ->and($event->scopes)->toBe(['openid']);

        $api->setAccessTokenClaim('project_id', 'p-2');
    });

    $claims = parseAccessToken($this->user->createToken('cli', ['openid'])->accessToken)->claims();

    expect($claims->get('sub'))->toBe((string) $this->user->id)
        ->and($claims->get('project_id'))->toBe('p-2')
        ->and($triggerCount)->toBe(1);
});

it('denies issuance before persisting when a trigger denies', function () {
    app(AccessTokenPipeline::class)->register('personal_access_token', fn (PersonalAccessTokenEvent $event, AccessTokenApi $api) => $api->deny('pat_blocked'));

    expect(fn () => $this->user->createToken('cli', ['openid']))->toThrow(TokenIssuanceDeniedException::class)
        ->and(AccessToken::query()->count())->toBe(0);
});
