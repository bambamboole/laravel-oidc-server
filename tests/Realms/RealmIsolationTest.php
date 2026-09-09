<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Keys\DatabaseSigningKeyStore;
use Bambamboole\LaravelOidc\Server\Keys\SigningKey;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeyGenerator;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\Models\Token;
use Bambamboole\LaravelOidc\Server\Realm\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Realm\RealmResolver;
use Bambamboole\LaravelOidc\Server\Token\TokenInspector;
use Workbench\App\Models\User;

/** Switches realms the way an application's host-derived resolver would. */
function enterRealm(string $realm): void
{
    app()->instance(RealmResolver::class, new class($realm) implements RealmResolver
    {
        public function __construct(private readonly string $realm) {}

        public function current(): string
        {
            return $this->realm;
        }
    });
}

it('does not resolve a client from another realm', function () {
    enterRealm('acme');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    expect(app(ClientRepository::class)->findActive($client->client_id))->not->toBeNull();

    enterRealm('globex');

    expect(app(ClientRepository::class)->findActive($client->client_id))->toBeNull()
        ->and(app(ClientRepository::class)->find($client->client_id))->toBeNull();
});

it('allows the same client_id in two realms', function () {
    enterRealm('acme');
    $first = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    $first->forceFill(['client_id' => 'shared-name'])->save();

    enterRealm('globex');
    $second = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    $second->forceFill(['client_id' => 'shared-name'])->save();

    expect(app(ClientRepository::class)->findActive('shared-name')?->getKey())->toBe($second->getKey());

    enterRealm('acme');

    expect(app(ClientRepository::class)->findActive('shared-name')?->getKey())->toBe($first->getKey());
});

it('does not resolve an access token from another realm', function () {
    enterRealm('acme');
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    (new Token)->forceFill([
        'realm_id' => 'acme',
        'id' => 'token-in-acme',
        'user_id' => $user->id,
        'client_id' => $client->id,
        'scopes' => ['openid'],
        'revoked' => false,
        'expires_at' => now()->addHour(),
    ])->save();

    expect(Token::query()->inRealm()->whereKey('token-in-acme')->exists())->toBeTrue();

    enterRealm('globex');

    expect(Token::query()->inRealm()->whereKey('token-in-acme')->exists())->toBeFalse();
});

it('keeps signing keys per realm', function () {
    $store = new DatabaseSigningKeyStore;
    app()->instance(SigningKeyStore::class, $store);
    app()->instance(SigningKeys::class, new SigningKeys($store));

    enterRealm('acme');
    $store->rotate((new SigningKeyGenerator($store))->generate());
    $acmeKid = $store->signingKey()->kid();

    enterRealm('globex');
    $store->rotate((new SigningKeyGenerator($store))->generate());
    $globexKid = $store->signingKey()->kid();

    expect($globexKid)->not->toBe($acmeKid)
        ->and(array_map(fn (SigningKey $key): string => $key->kid(), $store->verificationKeys()))->toBe([$globexKid]);

    enterRealm('acme');

    expect($store->signingKey()->kid())->toBe($acmeKid);
});

it('does not resolve a token through the inspector across realms', function () {
    enterRealm('acme');
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    $jwt = resourceServerBearer($this, [app(IssuerResolver::class)->url()]);

    expect(app(TokenInspector::class)->accessToken($jwt))->not->toBeNull();

    enterRealm('globex');

    expect(app(TokenInspector::class)->accessToken($jwt))->toBeNull();
});
