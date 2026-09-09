<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Realms\ConfiguredRealm;
use Bambamboole\LaravelOidc\Server\Realms\Realm;
use Bambamboole\LaravelOidc\Server\Realms\RealmRepository;
use Bambamboole\LaravelOidc\Server\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Realms\Settings\BrokeringSettings;
use Bambamboole\LaravelOidc\Server\Realms\Settings\ClientSettings;
use Bambamboole\LaravelOidc\Server\Realms\Settings\CredentialSettings;
use Bambamboole\LaravelOidc\Server\Realms\Settings\KeySettings;
use Bambamboole\LaravelOidc\Server\Realms\Settings\LoginSettings;
use Bambamboole\LaravelOidc\Server\Realms\Settings\ScopeSettings;
use Bambamboole\LaravelOidc\Server\Realms\Settings\SessionSettings;
use Bambamboole\LaravelOidc\Server\Realms\Settings\TokenSettings;
use Illuminate\Support\Facades\Route;

/** A realm the way an application model would implement it: its own settings, the rest configured. */
function realmWithSettings(string $id, ?TokenSettings $tokens = null, ?ClientSettings $clients = null): Realm
{
    return new class($id, $tokens, $clients) implements Realm
    {
        private readonly ConfiguredRealm $configured;

        public function __construct(string $id, private readonly ?TokenSettings $tokenSettings, private readonly ?ClientSettings $clientSettings)
        {
            $this->configured = new ConfiguredRealm($id);
        }

        public function id(): string
        {
            return $this->configured->id();
        }

        public function tokens(): TokenSettings
        {
            return $this->tokenSettings ?? $this->configured->tokens();
        }

        public function sessions(): SessionSettings
        {
            return $this->configured->sessions();
        }

        public function login(): LoginSettings
        {
            return $this->configured->login();
        }

        public function credentials(): CredentialSettings
        {
            return $this->configured->credentials();
        }

        public function brokering(): BrokeringSettings
        {
            return $this->configured->brokering();
        }

        public function scopes(): ScopeSettings
        {
            return $this->configured->scopes();
        }

        public function clients(): ClientSettings
        {
            return $this->clientSettings ?? $this->configured->clients();
        }

        public function keys(): KeySettings
        {
            return $this->configured->keys();
        }
    };
}

function bindRealms(Realm ...$realms): void
{
    app()->instance(RealmRepository::class, new class($realms) implements RealmRepository
    {
        /** @param  list<Realm>  $realms */
        public function __construct(private readonly array $realms) {}

        public function find(string $id): ?Realm
        {
            foreach ($this->realms as $realm) {
                if ($realm->id() === $id) {
                    return $realm;
                }
            }

            return null;
        }
    });
    app()->forgetInstance(RealmResolver::class);
}

it('issues tokens with the lifetime of the realm they are issued in', function () {
    config(['oidc.token_lifetimes.client_credentials' => 3600]);
    bindRealms(realmWithSettings('default'), realmWithSettings('short', new TokenSettings(clientCredentialsLifetime: 60)));

    $clients = [];

    foreach (['default', 'short'] as $realm) {
        config(['oidc.realm' => $realm]);
        $clients[$realm] = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    }

    $expiresIn = function (string $realm) use ($clients): int {
        // The authorization server is scoped per request, and the Route object
        // caches its controller instance; the test kernel keeps both across calls.
        app()->forgetScopedInstances();
        Route::getRoutes()->getByName('oidc.token')?->flushController();

        return (int) $this->post("/realms/{$realm}/oauth/token", [
            'grant_type' => 'client_credentials',
            'client_id' => $clients[$realm]->id,
            'client_secret' => $clients[$realm]->plainSecret,
            'scope' => '',
        ])->assertOk()->json('expires_in');
    };

    expect($expiresIn('default'))->toBeGreaterThan(3300)
        ->and($expiresIn('short'))->toBeLessThanOrEqual(60);
});

it('answers 404 for a realm the repository does not know', function () {
    bindRealms(realmWithSettings('default'));

    $this->get('/realms/ghost/.well-known/openid-configuration')->assertNotFound();
    $this->get('/realms/default/.well-known/openid-configuration')->assertOk();
});

it('advertises token exchange and registration per realm', function () {
    bindRealms(
        realmWithSettings('default'),
        realmWithSettings('locked', clients: new ClientSettings(dynamicRegistration: false, tokenExchange: false)),
    );
    config(['oidc.dcr.enabled' => true]);

    $open = $this->getJson('/realms/default/.well-known/openid-configuration')->json();
    $locked = $this->getJson('/realms/locked/.well-known/openid-configuration')->json();

    expect($open['grant_types_supported'])->toContain('urn:ietf:params:oauth:grant-type:token-exchange')
        ->and($open)->toHaveKey('registration_endpoint')
        ->and($locked['grant_types_supported'])->not->toContain('urn:ietf:params:oauth:grant-type:token-exchange')
        ->and($locked)->not->toHaveKey('registration_endpoint');
});
