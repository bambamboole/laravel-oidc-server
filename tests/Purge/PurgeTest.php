<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Consents\Models\Consent;
use Bambamboole\LaravelOidc\Server\Credentials\Models\PasswordHistory;
use Bambamboole\LaravelOidc\Server\Credentials\Models\RecoveryCode;
use Bambamboole\LaravelOidc\Server\Credentials\Models\TotpFactor;
use Bambamboole\LaravelOidc\Server\Purge\PurgeClient;
use Bambamboole\LaravelOidc\Server\Purge\PurgeRealm;
use Bambamboole\LaravelOidc\Server\Purge\PurgeUser;
use Bambamboole\LaravelOidc\Server\Realms\CurrentRealm;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\Models\SessionParticipant;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Workbench\App\Models\User;

function purgeTestUser(string $name): User
{
    return User::create(['name' => $name, 'email' => "{$name}@example.com", 'password' => 'secret']);
}

function purgeTestClient(?User $owner = null): Client
{
    return app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb'], user: $owner);
}

/** One row in every table the package keeps for a user signing in to a client. */
function seedHoldings(User $user, Client $client): void
{
    RefreshToken::factory()->forAccessToken(AccessToken::factory()->forClient($client)->forUser($user)->create())->create();
    AuthorizationCode::factory()->forClient($client)->forUser($user)->create();
    Consent::factory()->forClient($client)->forUser($user)->create();
    AuthenticationContext::factory()->forUser($user)->create();
    SessionParticipant::factory()->inSession(OidcSession::factory()->forUser($user)->create())->forClient($client)->create();
    passwordResetToken($user);
    SocialAccount::factory()->forUser($user)->create();
    PasswordHistory::factory()->forUser($user)->create();
    TotpFactor::factory()->forUser($user)->create();
    RecoveryCode::factory()->forUser($user)->create();
}

/** @return array<string, int> */
function packageRowCounts(?string $realm = null): array
{
    return collect(Schema::getTables())
        ->pluck('name')
        ->filter(fn (string $table): bool => str_starts_with($table, 'oidc_'))
        ->reject(fn (string $table): bool => $realm !== null && ! Schema::hasColumn($table, 'realm_id'))
        ->sort()
        ->mapWithKeys(fn (string $table): array => [$table => DB::table($table)->when($realm !== null, fn ($query) => $query->where('realm_id', $realm))->count()])
        ->all();
}

it('purges everything the package holds for a user, and nothing of anyone else', function (): void {
    $client = purgeTestClient();
    seedHoldings(purgeTestUser('bob'), $client);
    $untouched = packageRowCounts();
    $ada = purgeTestUser('ada');
    seedHoldings($ada, $client);

    app(PurgeUser::class)($ada);

    expect(packageRowCounts())->toBe($untouched);
});

it('purges the clients a user registered, with what they issued to others', function (): void {
    $ada = purgeTestUser('ada');
    $adasApp = purgeTestClient(owner: $ada);
    $clientSheUses = purgeTestClient();
    seedHoldings(purgeTestUser('bob'), $adasApp);

    app(PurgeUser::class)($ada);

    expect(Client::query()->pluck('id')->all())->toBe([$clientSheUses->id])
        ->and(AccessToken::query()->where('client_id', $adasApp->id)->exists())->toBeFalse();
});

it('purges a client with everything issued to it, and nothing of another client', function (): void {
    $user = purgeTestUser('ada');
    seedHoldings($user, purgeTestClient());
    $untouched = packageRowCounts();
    $client = purgeTestClient();
    RefreshToken::factory()->forAccessToken(AccessToken::factory()->forClient($client)->forUser($user)->create())->create();
    AuthorizationCode::factory()->forClient($client)->forUser($user)->create();
    Consent::factory()->forClient($client)->forUser($user)->create();
    SessionParticipant::factory()->forClient($client)->create(['session_id' => OidcSession::query()->value('id')]);

    app(PurgeClient::class)($client);

    expect(packageRowCounts())->toBe($untouched);
});

it('purges every row kept under a realm, and nothing of another realm', function (): void {
    CurrentRealm::runAs('globex', function (): void {
        generateRealmSigningKey();
        seedHoldings(purgeTestUser('bob'), purgeTestClient());
    });
    $globex = packageRowCounts('globex');
    CurrentRealm::runAs('acme', function (): void {
        generateRealmSigningKey();
        seedHoldings(purgeTestUser('ada'), purgeTestClient());
    });

    app(PurgeRealm::class)('acme');

    expect(packageRowCounts('acme'))->each->toBe(0)
        ->and(packageRowCounts('globex'))->toBe($globex)
        ->and(SessionParticipant::query()->whereNotIn('session_id', OidcSession::query()->select('id'))->exists())->toBeFalse();
});
