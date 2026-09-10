<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Tokens\Exceptions\TokenIssuanceDeniedException;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\CurrentAccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenApi;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\PersonalAccessTokenEvent;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Workbench\App\Models\User;

beforeEach(function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    app(ClientRepository::class)->createPersonalAccessGrantClient('PAT');
});

it('runs the personal-access trigger once and applies its claims to the issued token', function (): void {
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

it('stores the context a token is created with and serves it to the bearer guard', function (): void {
    Route::middleware('auth:oidc')->get('/context', fn (Request $request): array => $request->user()->currentAccessToken()?->context() ?? []);
    app(AccessTokenPipeline::class)->register('personal_access_token', function (PersonalAccessTokenEvent $event): void {
        expect($event->context)->toBe(['tenant_id' => 't-1']);
    });

    $result = $this->user->createToken('cli', ['openid'], ['tenant_id' => 't-1']);

    expect($result->token->context)->toBe(['tenant_id' => 't-1']);

    $this->withToken($result->accessToken)->getJson('/context')
        ->assertOk()
        ->assertExactJson(['tenant_id' => 't-1']);
});

it('leaves the context empty when a token is created without one', function (): void {
    $result = $this->user->createToken('cli', ['openid']);

    expect($result->token->context)->toBeNull()
        ->and(new CurrentAccessToken($result->token)->context())->toBe([]);
});

it('denies issuance before persisting when a trigger denies', function (): void {
    app(AccessTokenPipeline::class)->register('personal_access_token', fn (PersonalAccessTokenEvent $event, AccessTokenApi $api) => $api->deny('pat_blocked'));

    expect(fn () => $this->user->createToken('cli', ['openid']))->toThrow(TokenIssuanceDeniedException::class)
        ->and(AccessToken::query()->count())->toBe(0);
});
