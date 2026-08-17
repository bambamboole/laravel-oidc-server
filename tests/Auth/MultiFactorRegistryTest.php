<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts\FactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorChallenge;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorEnrollment;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorRegistry;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\FactorVerification;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\TotpFactorProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Workbench\App\Models\User;

it('registers factor providers by stable key and aggregates enrollments', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $provider = new class implements FactorProvider
    {
        public function key(): string
        {
            return 'custom';
        }

        public function isBackup(): bool
        {
            return false;
        }

        public function enrollments(Authenticatable $user): array
        {
            return [new FactorEnrollment('custom', 'enrollment-1', 'Custom key', now(), null)];
        }

        public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge
        {
            return new FactorChallenge($enrollment, ['prompt' => 'Touch key']);
        }

        public function verify(Authenticatable $user, FactorChallenge $challenge, array $input): FactorVerification
        {
            return new FactorVerification(true, ['custom']);
        }
    };

    $registry = new FactorRegistry;
    $registry->register($provider);

    expect($registry->get('custom'))->toBe($provider)
        ->and($registry->enrollments($user))->toHaveCount(1)
        ->and($registry->challengeableEnrollments($user))->toHaveCount(1);
});

it('limits configured challengeable enrollments to the challenge providers config', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $registry = app(FactorRegistry::class);
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();
    $user->passkeys()->create(['name' => 'Key', 'credential_id' => 'credential-id', 'credential' => []]);

    config(['oidc.auth.two_factor.challenge_providers' => ['totp', 'webauthn']]);
    expect(array_column($registry->configuredChallengeableEnrollments($user), 'providerKey'))
        ->toBe(['totp', 'webauthn']);

    config(['oidc.auth.two_factor.challenge_providers' => ['totp']]);
    expect(array_column($registry->configuredChallengeableEnrollments($user), 'providerKey'))
        ->toBe(['totp']);
});

it('reports whether a user has challengeable factors', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $registry = app(FactorRegistry::class);

    expect($registry->hasChallengeableFactors($user))->toBeFalse();

    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    expect($registry->hasChallengeableFactors($user))->toBeTrue();
});

it('collects enrollment options across providers in display order', function () {
    $options = app(FactorRegistry::class)->enrollmentOptions();

    expect(array_column($options, 'id'))->toBe(['passkey', 'security_key', 'totp'])
        ->and(array_column($options, 'sortOrder'))->toBe([10, 20, 30]);
});

it('leaves backup providers out of the enrollment options', function () {
    expect(array_column(app(FactorRegistry::class)->enrollmentOptions(), 'providerKey'))
        ->not->toContain('recovery_code');
});

it('resolves an enrollment option by id', function () {
    $registry = app(FactorRegistry::class);

    expect($registry->enrollmentOption('security_key')?->providerKey)->toBe('webauthn')
        ->and($registry->enrollmentOption('nope'))->toBeNull();
});

it('finds a confirmed enrollment by provider and id', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    $found = app(FactorRegistry::class)->findEnrollment($user, 'totp', (string) $factor->getKey());

    expect($found)->toBeInstanceOf(FactorEnrollment::class)
        ->and($found->providerKey)->toBe('totp');
});

it('returns null for an unknown provider, an unknown id, or another user', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'secret']);
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $registry = app(FactorRegistry::class);

    expect($registry->findEnrollment($user, 'nope', (string) $factor->getKey()))->toBeNull()
        ->and($registry->findEnrollment($user, 'totp', 'not-an-id'))->toBeNull()
        ->and($registry->findEnrollment($other, 'totp', (string) $factor->getKey()))->toBeNull();
});

it('rejects duplicate factor provider keys', function () {
    $registry = app(FactorRegistry::class);
    $provider = $registry->get('totp');

    expect(fn () => $registry->register($provider))->toThrow(LogicException::class);
});
