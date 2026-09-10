<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Bambamboole\LaravelOidc\Server\Brokering\SocialAccountManager;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Consents\ConsentRepository;
use Bambamboole\LaravelOidc\Server\Keys\DatabaseSigningKeyStore;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeyGenerator;
use Bambamboole\LaravelOidc\Server\Keys\StoredSigningKeys;
use Bambamboole\LaravelOidc\Server\Realms\ConfiguredRealm;
use Bambamboole\LaravelOidc\Server\Shared\Brokering\SocialUser;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyPair;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\Realm;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\PresentedTokenResolver;
use Bambamboole\LaravelOidc\Server\Tokens\TokenInspector;
use Workbench\App\Models\User;

/** Switches realms the way an application's host-derived resolver would. */
function enterRealm(string $realm): void
{
    app()->instance(RealmResolver::class, new readonly class($realm) implements RealmResolver
    {
        public function __construct(private string $realm) {}

        public function current(): Realm
        {
            return new ConfiguredRealm($this->realm);
        }
    });
}

it('does not resolve a client from another realm', function (): void {
    enterRealm('acme');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    expect(app(ClientRepository::class)->findActive($client->client_id))->not->toBeNull();

    enterRealm('globex');

    expect(app(ClientRepository::class)->findActive($client->client_id))->toBeNull()
        ->and(app(ClientRepository::class)->find($client->client_id))->toBeNull();
});

it('allows the same client_id in two realms', function (): void {
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

it('does not resolve an access token from another realm', function (): void {
    enterRealm('acme');
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    (new AccessToken)->forceFill([
        'realm_id' => 'acme',
        'id' => 'token-in-acme',
        'user_id' => $user->id,
        'client_id' => $client->id,
        'scopes' => ['openid'],
        'revoked' => false,
        'expires_at' => now()->addHour(),
    ])->save();

    expect(AccessToken::query()->inRealm()->whereKey('token-in-acme')->exists())->toBeTrue();

    enterRealm('globex');

    expect(AccessToken::query()->inRealm()->whereKey('token-in-acme')->exists())->toBeFalse();
});

it('keeps signing keys per realm', function (): void {
    $store = new DatabaseSigningKeyStore;
    app()->instance(SigningKeyStore::class, $store);
    app()->instance(SigningKeys::class, new StoredSigningKeys($store));

    enterRealm('acme');
    $store->rotate(new SigningKeyGenerator($store, app(RealmResolver::class))->generate());
    $acmeKid = $store->signingKey()->kid();

    enterRealm('globex');
    $store->rotate(new SigningKeyGenerator($store, app(RealmResolver::class))->generate());
    $globexKid = $store->signingKey()->kid();

    expect($globexKid)->not->toBe($acmeKid)
        ->and(array_map(fn (SigningKeyPair $key): string => $key->kid(), $store->verificationKeys()))->toBe([$globexKid]);

    enterRealm('acme');

    expect($store->signingKey()->kid())->toBe($acmeKid);
});

it('does not resolve a token through the inspector across realms', function (): void {
    enterRealm('acme');
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    $jwt = resourceServerBearer($this, [app(IssuerResolver::class)->url()]);

    expect(app(TokenInspector::class)->accessToken($jwt))->not->toBeNull();

    enterRealm('globex');

    expect(app(TokenInspector::class)->accessToken($jwt))->toBeNull();
});

it('does not resolve a refresh token from another realm', function (): void {
    enterRealm('acme');
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    [$value] = issueRefreshToken($this);

    expect(RefreshToken::query()->inRealm()->whereKey($value)->exists())->toBeTrue()
        ->and(app(PresentedTokenResolver::class)->resolve($value, 'refresh_token'))->not->toBeNull();

    enterRealm('globex');

    expect(RefreshToken::query()->inRealm()->whereKey($value)->exists())->toBeFalse()
        ->and(app(PresentedTokenResolver::class)->resolve($value, 'refresh_token'))->toBeNull();
});

it('keeps social accounts per realm, so one upstream identity may link to a different user in each', function (): void {
    $socialUser = new SocialUser(
        id: 'g-123',
        email: 'm@example.com',
        emailVerified: true,
        name: 'M',
        nickname: null,
        avatar: null,
        raw: ['sub' => 'g-123'],
        accessToken: 'at-1',
    );

    enterRealm('acme');
    $acmeUser = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    app(SocialAccountManager::class)->link($acmeUser, 'google', $socialUser);

    expect(app(SocialAccountManager::class)->findAccount('google', 'g-123')?->authenticatable->is($acmeUser))->toBeTrue();

    enterRealm('globex');

    expect(app(SocialAccountManager::class)->findAccount('google', 'g-123'))->toBeNull();

    $globexUser = User::create(['name' => 'G', 'email' => 'g@example.com', 'password' => 'x']);
    app(SocialAccountManager::class)->link($globexUser, 'google', $socialUser);

    expect(app(SocialAccountManager::class)->findAccount('google', 'g-123')?->authenticatable->is($globexUser))->toBeTrue()
        ->and(SocialAccount::query()->count())->toBe(2);
});

it('keeps consents per realm', function (): void {
    enterRealm('acme');
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    app(ConsentRepository::class)->grant((string) $user->id, (string) $client->getKey(), ['openid']);

    expect(app(ConsentRepository::class)->covers((string) $user->id, (string) $client->getKey(), ['openid']))->toBeTrue();

    enterRealm('globex');

    expect(app(ConsentRepository::class)->covers((string) $user->id, (string) $client->getKey(), ['openid']))->toBeFalse();
});
