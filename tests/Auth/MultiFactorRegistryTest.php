<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts\FactorProvider;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorChallenge;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorEnrollment;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorRegistry;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorResponse;
use Bambamboole\LaravelOidc\Auth\MultiFactor\FactorVerification;
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

        public function verify(Authenticatable $user, FactorChallenge $challenge, FactorResponse $response): FactorVerification
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

it('rejects duplicate factor provider keys', function () {
    $registry = app(FactorRegistry::class);
    $provider = $registry->get('totp');

    expect(fn () => $registry->register($provider))->toThrow(LogicException::class);
});
