<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Realms\Http\Middleware\ResolveRealm;
use Bambamboole\LaravelOidc\Server\Sessions\BackChannel\SendBackChannelLogout;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Shared\Context\OidcContext;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Bambamboole\LaravelOidc\Server\Tests\Realms\RecordResolvedRealm;
use Bambamboole\LaravelOidc\Server\Tests\Realms\RoutesRealmsByPath;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Workbench\App\Models\User;

uses(RoutesRealmsByPath::class, InteractsWithOidc::class);

beforeEach(function (): void {
    config([
        'oidc.realm' => 'default',
        'oidc.issuer' => 'https://id.example.com',
        'queue.default' => 'database',
    ]);

    RecordResolvedRealm::forget();

    Route::middleware(ResolveRealm::class)
        ->prefix('realms/{realm}')
        ->where(['realm' => '[A-Za-z0-9._-]+'])
        ->get('test/queue', function (): string {
            RecordResolvedRealm::dispatch();

            return 'queued';
        });
});

it('publishes the realm a request resolved to', function (): void {
    $this->get('/realms/acme/.well-known/openid-configuration')->assertOk();

    expect(Context::get(OidcContext::REALM))->toBe('acme');
});

it('publishes the client an authorize request names, and the one that authenticates at the token endpoint', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => bcrypt('secret')]);
    $client = $this->createOidcClient();

    $this->authorizeAndApprove($user, $client)->response->assertOk();

    expect(Context::get(OidcContext::CLIENT))->toBe($client->client_id);
});

it('records the client even when the authorize request is rejected afterwards', function (): void {
    $client = $this->createOidcClient();

    $this->get(route('oidc.authorize', ['client_id' => $client->client_id, 'redirect_uri' => 'https://attacker.test/cb']))
        ->assertStatus(400);

    expect(Context::get(OidcContext::CLIENT))->toBe($client->client_id);
});

it('resolves the realm a job was dispatched from, not the configured one', function (): void {
    $this->get('/realms/acme/test/queue')->assertOk();

    forgetRequest();
    workQueue();

    expect(RecordResolvedRealm::$seen['realm'])->toBe('acme')
        ->and(RecordResolvedRealm::$seen['issuer'])->toBe('https://id.example.com/realms/acme');
});

// The realm has to be the URL default before the job body runs, or a queued
// password-reset notification links the user into the wrong realm.
it('generates realm urls inside a queued job', function (): void {
    $this->get('/realms/acme/test/queue')->assertOk();

    forgetRequest();
    workQueue();

    expect(RecordResolvedRealm::$seen['authorize_path'])->toBe('/realms/acme/oauth/authorize');
});

it('falls back to the configured realm for a job dispatched outside a request', function (): void {
    RecordResolvedRealm::dispatch();

    forgetRequest();
    workQueue();

    expect(RecordResolvedRealm::$seen['realm'])->toBe('default')
        ->and(RecordResolvedRealm::$seen['authorize_path'])->toBe('/realms/default/oauth/authorize');
});

it('carries the client of the request that queued the job', function (): void {
    $client = $this->createOidcClient();

    $this->get(route('oidc.authorize', ['client_id' => $client->client_id, 'redirect_uri' => 'https://attacker.test/cb']))
        ->assertStatus(400);

    RecordResolvedRealm::dispatch();

    forgetRequest();
    workQueue();

    expect(RecordResolvedRealm::$seen['client'])->toBe($client->client_id);
});

// The realm-scoped lookups inside the job are the point: before the realm
// travelled with it, this job found no session in the worker's default realm
// and returned without notifying anyone.
it('sends a back-channel logout for the realm the job was dispatched from', function (): void {
    Http::fake();

    $this->get('/realms/acme/.well-known/openid-configuration')->assertOk();
    generateRealmSigningKey();

    $sid = app(OidcSessionRepository::class)->start('9');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    $client->forceFill(['backchannel_logout_uri' => 'https://rp.test/bclo'])->save();

    SendBackChannelLogout::dispatch($sid, (string) $client->id);

    forgetRequest();
    workQueue();

    Http::assertSent(fn (ClientRequest $request): bool => $request->url() === 'https://rp.test/bclo'
        && parseAccessToken((string) $request['logout_token'])->claims()->get('iss') === 'https://id.example.com/realms/acme');
});

it('falls back to the configured realm outside a matched route', function (): void {
    config(['oidc.realm' => 'fallback']);

    app()->instance('request', new Request);

    expect(app(RealmResolver::class)->current()->identifier())->toBe('fallback');
});
