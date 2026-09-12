<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Server\Authentication\Models\PasswordResetToken;
use Bambamboole\LaravelOidc\Server\Brokering\Models\SocialAccount;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Consents\Models\Consent;
use Bambamboole\LaravelOidc\Server\Credentials\Models\PasswordHistory;
use Bambamboole\LaravelOidc\Server\Credentials\Models\RecoveryCode;
use Bambamboole\LaravelOidc\Server\Credentials\Models\TotpFactor;
use Bambamboole\LaravelOidc\Server\Realms\CurrentRealm;
use Bambamboole\LaravelOidc\Server\Sessions\Models\OidcSession;
use Bambamboole\LaravelOidc\Server\Sessions\Models\SessionParticipant;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use Workbench\App\Models\User;

it('inserts a row the schema accepts', function (Factory $factory): void {
    expect($factory->create()->exists)->toBeTrue();
})->with([
    'access token' => fn (): Factory => AccessToken::factory(),
    'client' => fn (): Factory => Client::factory(),
    'authentication context' => fn (): Factory => AuthenticationContext::factory(),
    'authorization code' => fn (): Factory => AuthorizationCode::factory(),
    'consent' => fn (): Factory => Consent::factory(),
    'session' => fn (): Factory => OidcSession::factory(),
    'session participant' => fn (): Factory => SessionParticipant::factory(),
    'refresh token' => fn (): Factory => RefreshToken::factory(),
    'social account' => fn (): Factory => SocialAccount::factory(),
    'totp factor' => fn (): Factory => TotpFactor::factory(),
    'recovery code' => fn (): Factory => RecoveryCode::factory(),
    'password history' => fn (): Factory => PasswordHistory::factory(),
    'password reset token' => fn (): Factory => PasswordResetToken::factory(),
]);

it('issues a row to a client inside the client\'s realm', function (): void {
    $client = CurrentRealm::runAs('acme', fn () => app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']));
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('secret')]);

    $token = AccessToken::factory()->forClient($client)->forUser($user)->create();

    expect($token->only('realm_id', 'client_id', 'user_id'))->toBe([
        'realm_id' => 'acme',
        'client_id' => $client->getKey(),
        'user_id' => $user->getKey(),
    ]);
});
