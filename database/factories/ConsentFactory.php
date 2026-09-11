<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Database\Factories;

use Bambamboole\LaravelOidc\Server\Consents\Models\Consent;
use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForClient;
use Bambamboole\LaravelOidc\Server\Database\Factories\Concerns\ForUser;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<Consent>
 */
class ConsentFactory extends Factory
{
    use ForClient, ForUser;

    protected $model = Consent::class;

    public function definition(): array
    {
        return [
            'realm_id' => Consent::currentRealm(),
            'user_id' => (string) Str::uuid(),
            'client_id' => (string) Str::uuid(),
            'resource' => fn (): string => app(IssuerResolver::class)->url(),
            'scopes' => ['openid'],
            'granted_at' => now(),
        ];
    }

    public function revoked(): static
    {
        return $this->state(['revoked_at' => now()]);
    }
}
