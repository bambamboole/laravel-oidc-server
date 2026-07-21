<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Clients\FirstPartyClientProvisioner;
use Bambamboole\LaravelOidc\Clients\FirstPartyClientProvisioningException;
use Bambamboole\LaravelOidc\Clients\FirstPartyClientProvisioningOutcome;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Workbench\App\Models\User;

const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';

it('creates a confidential managed client and returns its plain secret once', function () {
    $result = app(FirstPartyClientProvisioner::class)->provision(
        name: 'First-party app',
        redirectUris: ['https://app.test/login/callback'],
        postLogoutRedirectUris: ['https://app.test'],
        allowedExchangeAudiences: ['https://api.test/orders'],
    );

    expect($result->outcome)->toBe(FirstPartyClientProvisioningOutcome::Created)
        ->and($result->clientSecret)->toBeString()->not->toBeEmpty()
        ->and(Hash::check($result->clientSecret, (string) $result->client->getRawOriginal('secret')))->toBeTrue()
        ->and($result->client->getRawOriginal('oidc_provisioning_key'))->toBe('first-party')
        ->and($result->client->getAttribute('redirect_uris'))->toBe(['https://app.test/login/callback'])
        ->and(json_decode((string) $result->client->getRawOriginal('post_logout_redirect_uris'), true, flags: JSON_THROW_ON_ERROR))->toBe(['https://app.test'])
        ->and(json_decode((string) $result->client->getRawOriginal('allowed_exchange_audiences'), true, flags: JSON_THROW_ON_ERROR))->toBe(['https://api.test/orders'])
        ->and($result->client->getAttribute('grant_types'))->toBe(['authorization_code', 'refresh_token', TOKEN_EXCHANGE_GRANT]);

    expect($result->created)->toBeTrue();
});

it('reconciles the managed client without rotating its secret', function () {
    $provisioner = app(FirstPartyClientProvisioner::class);
    $created = $provisioner->provision('Old name', ['https://old.test/callback']);
    $storedSecret = $created->client->getRawOriginal('secret');

    $result = $provisioner->provision(
        'New name',
        ['https://new.test/callback', 'https://new.test/callback'],
        ['https://new.test'],
    );

    expect($result->outcome)->toBe(FirstPartyClientProvisioningOutcome::Reconciled)
        ->and($result->clientId)->toBe($created->clientId)
        ->and($result->clientSecret)->toBeNull()
        ->and($result->client->getAttribute('name'))->toBe('New name')
        ->and($result->client->getAttribute('redirect_uris'))->toBe(['https://new.test/callback'])
        ->and($result->client->getRawOriginal('secret'))->toBe($storedSecret)
        ->and($result->client->getAttribute('grant_types'))->toBe(['authorization_code', 'refresh_token']);

    expect($result->created)->toBeFalse();
});

it('reconciles the managed client with a matching credential and returns the verified secret', function () {
    $provisioner = app(FirstPartyClientProvisioner::class);
    $created = $provisioner->provision('Old name', ['https://old.test/callback']);
    $storedSecret = $created->client->getRawOriginal('secret');

    $result = $provisioner->provision(
        name: 'New name',
        redirectUris: ['https://new.test/callback'],
        postLogoutRedirectUris: ['https://new.test'],
        allowedExchangeAudiences: ['https://api.test/orders'],
        existingClientSecret: $created->clientSecret,
    );

    expect($created->clientSecret)->toBeString()->not->toBeEmpty()
        ->and($result->outcome)->toBe(FirstPartyClientProvisioningOutcome::Reconciled)
        ->and($result->clientId)->toBe($created->clientId)
        ->and($result->clientSecret)->toBe($created->clientSecret)
        ->and($result->client->getAttribute('name'))->toBe('New name')
        ->and($result->client->getAttribute('redirect_uris'))->toBe(['https://new.test/callback'])
        ->and($result->client->getRawOriginal('secret'))->toBe($storedSecret)
        ->and($result->client->getAttribute('grant_types'))->toBe(['authorization_code', 'refresh_token', TOKEN_EXCHANGE_GRANT]);
});

it('rejects a mismatched managed client credential without mutating the client', function (string $existingClientSecret) {
    $provisioner = app(FirstPartyClientProvisioner::class);
    $created = $provisioner->provision('Original name', ['https://original.test/callback']);
    $originalAttributes = $created->client->getRawOriginal();

    expect(fn () => $provisioner->provision(
        name: 'Changed name',
        redirectUris: ['https://changed.test/callback'],
        postLogoutRedirectUris: ['https://changed.test'],
        allowedExchangeAudiences: ['https://api.test/changed'],
        existingClientSecret: $existingClientSecret,
    ))->toThrow(
        FirstPartyClientProvisioningException::class,
        'The existing first-party client secret does not match.',
    );

    expect($created->client->refresh()->getRawOriginal())->toBe($originalAttributes);
})->with([
    'wrong secret' => 'wrong-secret',
    'empty secret' => '',
]);

it('creates a managed client with a new credential when a stale existing credential is supplied', function () {
    $result = app(FirstPartyClientProvisioner::class)->provision(
        name: 'First-party app',
        redirectUris: ['https://app.test/login/callback'],
        existingClientSecret: 'stale-secret',
    );

    expect($result->outcome)->toBe(FirstPartyClientProvisioningOutcome::Created)
        ->and($result->clientSecret)->toBeString()->not->toBeEmpty()->not->toBe('stale-secret')
        ->and(Hash::check($result->clientSecret, (string) $result->client->getRawOriginal('secret')))->toBeTrue();
});

it('adopts an explicit eligible client and then rotates only when requested', function () {
    $legacy = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Legacy', ['https://legacy.test/callback']);
    $oldHash = $legacy->getRawOriginal('secret');

    $adopted = app(FirstPartyClientProvisioner::class)->provision(
        'Adopted',
        ['https://app.test/login/callback'],
        adoptClientId: (string) $legacy->getKey(),
    );

    $rotated = app(FirstPartyClientProvisioner::class)->provision(
        'Adopted',
        ['https://app.test/login/callback'],
        rotateSecret: true,
    );

    expect($adopted->clientId)->toBe((string) $legacy->getKey())
        ->and($adopted->clientSecret)->toBeNull()
        ->and($rotated->outcome)->toBe(FirstPartyClientProvisioningOutcome::Rotated)
        ->and($rotated->clientSecret)->toBeString()->not->toBeEmpty()
        ->and($rotated->client->getRawOriginal('secret'))->not->toBe($oldHash);
});

it('adopts an explicit eligible client after verifying its credential', function () {
    $legacy = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Legacy', ['https://legacy.test/callback']);
    $storedSecret = $legacy->getRawOriginal('secret');

    $result = app(FirstPartyClientProvisioner::class)->provision(
        name: 'Adopted',
        redirectUris: ['https://app.test/login/callback'],
        adoptClientId: (string) $legacy->getKey(),
        existingClientSecret: $legacy->plainSecret,
    );

    expect($result->outcome)->toBe(FirstPartyClientProvisioningOutcome::Reconciled)
        ->and($result->clientId)->toBe((string) $legacy->getKey())
        ->and($result->clientSecret)->toBe($legacy->plainSecret)
        ->and($result->client->getRawOriginal('secret'))->toBe($storedSecret)
        ->and($result->client->getRawOriginal('oidc_provisioning_key'))->toBe('first-party');
});

it('rejects a mismatched adoption credential without mutating the client', function () {
    $legacy = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Legacy', ['https://legacy.test/callback']);
    $originalAttributes = $legacy->refresh()->getRawOriginal();

    expect(fn () => app(FirstPartyClientProvisioner::class)->provision(
        name: 'Adopted',
        redirectUris: ['https://app.test/login/callback'],
        adoptClientId: (string) $legacy->getKey(),
        existingClientSecret: 'wrong-secret',
    ))->toThrow(FirstPartyClientProvisioningException::class, 'secret does not match');

    expect($legacy->refresh()->getRawOriginal())->toBe($originalAttributes);
});

it('verifies the existing credential before rotating it', function () {
    $provisioner = app(FirstPartyClientProvisioner::class);
    $created = $provisioner->provision('Original name', ['https://original.test/callback']);
    $originalHash = $created->client->getRawOriginal('secret');

    expect(fn () => $provisioner->provision(
        name: 'Changed name',
        redirectUris: ['https://changed.test/callback'],
        rotateSecret: true,
        existingClientSecret: 'wrong-secret',
    ))->toThrow(FirstPartyClientProvisioningException::class, 'secret does not match');

    expect($created->client->refresh()->getAttribute('name'))->toBe('Original name')
        ->and($created->client->getRawOriginal('secret'))->toBe($originalHash);

    $rotated = $provisioner->provision(
        name: 'Changed name',
        redirectUris: ['https://changed.test/callback'],
        rotateSecret: true,
        existingClientSecret: $created->clientSecret,
    );

    expect($rotated->outcome)->toBe(FirstPartyClientProvisioningOutcome::Rotated)
        ->and($rotated->clientSecret)->toBeString()->not->toBeEmpty()->not->toBe($created->clientSecret)
        ->and(Hash::check($rotated->clientSecret, (string) $rotated->client->getRawOriginal('secret')))->toBeTrue();
});

it('verifies the existing credential inside the passport transaction', function () {
    $provisioner = app(FirstPartyClientProvisioner::class);
    $created = $provisioner->provision('Original name', ['https://original.test/callback']);
    $storedHash = (string) $created->client->getRawOriginal('secret');
    $connectionName = config('passport.connection');
    $connection = DB::connection(is_string($connectionName) ? $connectionName : null);
    $delegate = app(Hasher::class);
    $spy = new class($delegate, $connection) implements Hasher
    {
        public bool $checkedInsideTransaction = false;

        public ?string $checkedHash = null;

        public function __construct(
            private readonly Hasher $delegate,
            private readonly ConnectionInterface $connection,
        ) {}

        /** @return array<string, mixed> */
        public function info(mixed $hashedValue): array
        {
            return $this->delegate->info($hashedValue);
        }

        /** @param array<string, mixed> $options */
        public function make(#[SensitiveParameter] mixed $value, array $options = []): string
        {
            return $this->delegate->make($value, $options);
        }

        /** @param array<string, mixed> $options */
        public function check(#[SensitiveParameter] mixed $value, mixed $hashedValue, array $options = []): bool
        {
            $this->checkedInsideTransaction = $this->connection->transactionLevel() > 0;
            $this->checkedHash = $hashedValue;

            return $this->delegate->check($value, $hashedValue, $options);
        }

        /** @param array<string, mixed> $options */
        public function needsRehash(mixed $hashedValue, array $options = []): bool
        {
            return $this->delegate->needsRehash($hashedValue, $options);
        }
    };

    app()->instance(Hasher::class, $spy);
    app()->forgetInstance(FirstPartyClientProvisioner::class);

    app(FirstPartyClientProvisioner::class)->provision(
        name: 'Changed name',
        redirectUris: ['https://changed.test/callback'],
        existingClientSecret: $created->clientSecret,
    );

    expect($spy->checkedInsideTransaction)->toBeTrue()
        ->and($spy->checkedHash)->toBe($storedHash);
});

it('rejects unsafe adoption targets', function (Closure $mutate, string $message) {
    $client = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Unsafe', ['https://unsafe.test/callback']);
    $mutate($client);

    expect(fn () => app(FirstPartyClientProvisioner::class)->provision(
        'Unsafe',
        ['https://app.test/login/callback'],
        adoptClientId: (string) $client->getKey(),
    ))->toThrow(FirstPartyClientProvisioningException::class, $message);
})->with([
    'revoked' => [fn ($client) => $client->forceFill(['revoked' => true])->save(), 'revoked'],
    'public' => [fn ($client) => $client->forceFill(['secret' => null])->save(), 'confidential'],
]);

it('rejects a user-owned adoption target', function () {
    $user = User::create([
        'name' => 'Owner',
        'email' => 'owner@example.com',
        'password' => 'secret',
    ]);
    $client = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient(
            'User-owned',
            ['https://owned.test/callback'],
            user: $user,
        );

    expect(fn () => app(FirstPartyClientProvisioner::class)->provision(
        'User-owned',
        ['https://app.test/login/callback'],
        adoptClientId: (string) $client->getKey(),
    ))->toThrow(FirstPartyClientProvisioningException::class, 'must not be owned');
});

it('rejects exchange audiences when token exchange is disabled', function () {
    config(['oidc.token_exchange.enabled' => false]);

    expect(fn () => app(FirstPartyClientProvisioner::class)->provision(
        'First-party app',
        ['https://app.test/login/callback'],
        allowedExchangeAudiences: ['https://api.test/orders'],
    ))->toThrow(FirstPartyClientProvisioningException::class, 'disabled');

    expect(Passport::client()->newQuery()->where('oidc_provisioning_key', 'first-party')->exists())->toBeFalse();
});

it('does not revoke existing tokens when rotating the client secret', function () {
    $provisioner = app(FirstPartyClientProvisioner::class);
    $created = $provisioner->provision('First-party app', ['https://app.test/login/callback']);
    $token = Passport::token()->newQuery()->create([
        'id' => 'existing-token',
        'client_id' => $created->clientId,
        'scopes' => [],
        'revoked' => false,
        'expires_at' => now()->addHour(),
    ]);

    $provisioner->provision(
        'First-party app',
        ['https://app.test/login/callback'],
        rotateSecret: true,
    );

    expect($token->refresh()->getAttribute('revoked'))->toBeFalse();
});

it('rejects invalid provisioning input before writing', function (
    string $name,
    array $redirectUris,
    array $audiences,
    string $message,
    array $postLogoutRedirectUris = [],
) {
    expect(fn () => app(FirstPartyClientProvisioner::class)->provision(
        $name,
        $redirectUris,
        postLogoutRedirectUris: $postLogoutRedirectUris,
        allowedExchangeAudiences: $audiences,
    ))->toThrow(FirstPartyClientProvisioningException::class, $message);

    expect(Passport::client()->newQuery()->where('oidc_provisioning_key', 'first-party')->exists())
        ->toBeFalse();
})->with([
    'blank name' => [' ', ['https://app.test/callback'], [], 'name'],
    'missing redirect' => ['App', [], [], 'At least one redirect URI'],
    'redirect user info' => ['App', ['https://user@app.test/callback'], [], 'without user information'],
    'redirect fragment' => ['App', ['https://app.test/callback#fragment'], [], 'without user information or a fragment'],
    'redirect raw space' => ['App', ['https://app.test/call back'], [], 'absolute HTTP(S) URI'],
    'redirect control character' => ['App', ["https://app.test/callback\nnext"], [], 'absolute HTTP(S) URI'],
    'redirect backslash' => ['App', ['https://app.test\\callback'], [], 'absolute HTTP(S) URI'],
    'redirect malformed percent escape' => ['App', ['https://app.test/callback%2'], [], 'absolute HTTP(S) URI'],
    'redirect missing host' => ['App', ['https:///callback'], [], 'absolute HTTP(S) URI'],
    'redirect malformed host' => ['App', ['https://app_test/callback'], [], 'absolute HTTP(S) URI'],
    'post logout raw space' => ['App', ['https://app.test/callback'], [], 'absolute HTTP(S) URI', ['https://app.test/logged out']],
    'relative audience' => ['App', ['https://app.test/callback'], ['/orders'], 'absolute URI'],
    'audience raw space' => ['App', ['https://app.test/callback'], ['urn:example:order details'], 'absolute URI'],
    'audience control character' => ['App', ['https://app.test/callback'], ["urn:example:orders\tadmin"], 'absolute URI'],
    'audience backslash' => ['App', ['https://app.test/callback'], ['urn:example:orders\\admin'], 'absolute URI'],
    'audience malformed percent escape' => ['App', ['https://app.test/callback'], ['urn:example:orders%2'], 'absolute URI'],
    'audience invalid scheme' => ['App', ['https://app.test/callback'], ['1abc:orders'], 'absolute URI'],
    'audience incomplete https URI' => ['App', ['https://app.test/callback'], ['https://'], 'absolute URI'],
    'audience incomplete URN' => ['App', ['https://app.test/callback'], ['urn:example:'], 'absolute URI'],
    'audience one-character URN NID' => ['App', ['https://app.test/callback'], ['urn:a:orders'], 'absolute URI'],
    'audience leading-hyphen URN NID' => ['App', ['https://app.test/callback'], ['urn:-example:orders'], 'absolute URI'],
    'audience trailing-hyphen URN NID' => ['App', ['https://app.test/callback'], ['urn:example-:orders'], 'absolute URI'],
    'audience excessive-length URN NID' => ['App', ['https://app.test/callback'], ['urn:'.str_repeat('a', 33).':orders'], 'absolute URI'],
    'audience raw pipe' => ['App', ['https://app.test/callback'], ['urn:example:ord|ers'], 'absolute URI'],
    'audience raw quote' => ['App', ['https://app.test/callback'], ['urn:example:"orders'], 'absolute URI'],
    'audience unmatched bracket' => ['App', ['https://app.test/callback'], ['urn:example:[orders'], 'absolute URI'],
]);

it('does not require the optional scheme-specific League URN parser', function () {
    $source = file_get_contents(dirname(__DIR__, 2).'/src/Clients/FirstPartyClientProvisioner.php');

    expect($source)->toBeString()
        ->not->toContain('League\\Uri\\Urn');
});

it('accepts valid RFC 8141 optional components', function (string $audience) {
    $result = app(FirstPartyClientProvisioner::class)->provision(
        'First-party app',
        ['https://app.test/callback'],
        allowedExchangeAudiences: [$audience],
    );

    expect(json_decode((string) $result->client->getRawOriginal('allowed_exchange_audiences'), true, flags: JSON_THROW_ON_ERROR))
        ->toBe([$audience]);
})->with([
    'question mark in r-component' => 'urn:example:orders?+a?b',
    'empty fragment' => 'urn:example:orders#',
]);

it('accepts absolute URI audience identifiers with hierarchical and non-hierarchical schemes', function () {
    $result = app(FirstPartyClientProvisioner::class)->provision(
        'First-party app',
        ['https://app.test/callback'],
        allowedExchangeAudiences: ['urn:example:orders', 'https://api.test/orders', 'mailto:orders@example.com'],
    );

    expect(json_decode((string) $result->client->getRawOriginal('allowed_exchange_audiences'), true, flags: JSON_THROW_ON_ERROR))
        ->toBe(['urn:example:orders', 'https://api.test/orders', 'mailto:orders@example.com']);
});

it('rejects adoption when another managed client already exists', function () {
    $provisioner = app(FirstPartyClientProvisioner::class);
    $managed = $provisioner->provision('Managed', ['https://managed.test/callback']);
    $other = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Other', ['https://other.test/callback']);

    expect(fn () => $provisioner->provision(
        'Other',
        ['https://other.test/callback'],
        adoptClientId: (string) $other->getKey(),
    ))->toThrow(FirstPartyClientProvisioningException::class, 'different client');

    expect($managed->client->refresh()->getRawOriginal('oidc_provisioning_key'))->toBe('first-party')
        ->and($other->refresh()->getRawOriginal('oidc_provisioning_key'))->toBeNull();
});

it('normalizes metadata and removes exchange capability when audiences become empty', function () {
    $provisioner = app(FirstPartyClientProvisioner::class);
    $provisioner->provision(
        ' First-party app ',
        [' https://app.test/second ', 'https://app.test/first', 'https://app.test/second'],
        [' https://app.test/second ', 'https://app.test/first', 'https://app.test/second'],
        [' https://api.test/second ', 'https://api.test/first', 'https://api.test/second'],
    );

    $normalized = Passport::client()->newQuery()
        ->where('oidc_provisioning_key', 'first-party')
        ->firstOrFail();

    expect($normalized->getAttribute('name'))->toBe('First-party app')
        ->and($normalized->getAttribute('redirect_uris'))->toBe(['https://app.test/second', 'https://app.test/first'])
        ->and(json_decode((string) $normalized->getRawOriginal('post_logout_redirect_uris'), true, flags: JSON_THROW_ON_ERROR))
        ->toBe(['https://app.test/second', 'https://app.test/first'])
        ->and(json_decode((string) $normalized->getRawOriginal('allowed_exchange_audiences'), true, flags: JSON_THROW_ON_ERROR))
        ->toBe(['https://api.test/second', 'https://api.test/first']);

    $result = $provisioner->provision('First-party app', ['https://app.test/callback']);

    expect($result->client->getAttribute('redirect_uris'))->toBe(['https://app.test/callback'])
        ->and($result->client->getAttribute('grant_types'))->toBe(['authorization_code', 'refresh_token'])
        ->and(json_decode((string) $result->client->getRawOriginal('allowed_exchange_audiences'), true, flags: JSON_THROW_ON_ERROR))->toBe([]);
});

it('preserves an explicit adoption target when recovering from a provisioning key race', function () {
    $clients = app(ClientRepository::class);
    $winner = $clients->createAuthorizationCodeGrantClient('Winner', ['https://winner.test/callback']);
    $loser = $clients->createAuthorizationCodeGrantClient('Loser', ['https://loser.test/callback']);
    $winner->forceFill(['oidc_provisioning_key' => 'first-party'])->save();

    $clientModel = Passport::client();
    $clientModelClass = $clientModel::class;
    $scopeApplications = 0;

    $clientModelClass::addGlobalScope(
        'simulate-provisioning-key-race',
        function (Builder $query) use (&$scopeApplications, $winner): void {
            $scopeApplications++;

            if ($scopeApplications === 1) {
                $query->where($query->getModel()->getQualifiedKeyName(), '!=', $winner->getKey());
            }
        },
    );

    try {
        expect(fn () => app(FirstPartyClientProvisioner::class)->provision(
            'Losing adoption',
            ['https://loser.test/callback'],
            adoptClientId: (string) $loser->getKey(),
        ))->toThrow(FirstPartyClientProvisioningException::class, 'different client');

        expect($winner->refresh()->getAttribute('name'))->toBe('Winner')
            ->and($loser->refresh()->getRawOriginal('oidc_provisioning_key'))->toBeNull();
    } finally {
        $clientModelClass::clearBootedModels();
    }
});

it('revalidates the winning credential when recovering from a provisioning key race', function () {
    $winner = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Winner', ['https://winner.test/callback']);
    $winningSecret = $winner->plainSecret;
    $winner->forceFill(['oidc_provisioning_key' => 'first-party'])->save();

    $clientModel = Passport::client();
    $clientModelClass = $clientModel::class;
    $scopeApplications = 0;

    $clientModelClass::addGlobalScope(
        'simulate-credential-provisioning-key-race',
        function (Builder $query) use (&$scopeApplications, $winner): void {
            $scopeApplications++;

            if ($scopeApplications === 1) {
                $query->where($query->getModel()->getQualifiedKeyName(), '!=', $winner->getKey());
            }
        },
    );

    try {
        $result = app(FirstPartyClientProvisioner::class)->provision(
            name: 'Reconciled winner',
            redirectUris: ['https://winner.test/new-callback'],
            existingClientSecret: $winningSecret,
        );

        expect($result->outcome)->toBe(FirstPartyClientProvisioningOutcome::Reconciled)
            ->and($result->clientId)->toBe((string) $winner->getKey())
            ->and($result->clientSecret)->toBe($winningSecret)
            ->and($winner->refresh()->getAttribute('name'))->toBe('Reconciled winner')
            ->and($winner->getAttribute('redirect_uris'))->toBe(['https://winner.test/new-callback']);
    } finally {
        $clientModelClass::clearBootedModels();
    }
});
