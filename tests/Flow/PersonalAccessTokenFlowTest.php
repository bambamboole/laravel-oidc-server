<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Auth\Pipeline\PersonalAccessTokenEvent;
use Bambamboole\LaravelOidc\Facades\Oidc;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Exception\OAuthServerException;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    app(ClientRepository::class)->createPersonalAccessGrantClient('PAT', 'users');
});

it('runs the personal-access trigger once and applies its access-token claims', function () {
    $triggerCount = 0;

    Oidc::personalAccessToken(function (PersonalAccessTokenEvent $event, AccessTokenApi $api) use (&$triggerCount): void {
        $triggerCount++;

        expect($event->user->getAuthIdentifier())->toBe($this->user->id)
            ->and($event->scopes)->toBe(['openid']);

        $api->setAccessTokenClaim('project_id', 'p-2');
    });

    $jwt = $this->user->createToken('cli', ['openid'])->accessToken;

    expect(parseAccessToken($jwt)->claims()->get('project_id'))->toBe('p-2')
        ->and($triggerCount)->toBe(1);
});

it('denies personal-access issuance before persisting an access token', function () {
    Oidc::personalAccessToken(function (PersonalAccessTokenEvent $event, AccessTokenApi $api): void {
        $api->deny('pat_blocked');
    });

    expect(fn () => $this->user->createToken('cli', ['openid']))
        ->toThrow(OAuthServerException::class);

    expect(Passport::token()->newQuery()->count())->toBe(0);
});

it('does not fire the personal-access trigger for other grants', function () {
    $triggerRan = false;

    Oidc::personalAccessToken(function () use (&$triggerRan): void {
        $triggerRan = true;
    });

    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->id,
        'client_secret' => $client->plainSecret,
        'scope' => '',
    ])->assertOk();

    expect($triggerRan)->toBeFalse();
});

it('issues personal access tokens unchanged when no trigger is registered', function () {
    $jwt = $this->user->createToken('cli', ['openid'])->accessToken;

    expect(parseAccessToken($jwt)->claims()->get('sub'))->toBe((string) $this->user->id);
});
