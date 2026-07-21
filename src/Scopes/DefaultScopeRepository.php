<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Scopes;

use Bambamboole\LaravelOidc\Contracts\ScopeRepository;
use Illuminate\Support\Collection;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\ClientEntityInterface;

class DefaultScopeRepository implements ScopeRepository
{
    private const array OIDC_SCOPES = [
        'openid' => 'Authenticate with your account',
        'profile' => 'Access your basic profile information',
        'email' => 'Access your email address',
        'address' => 'Access your postal address',
        'phone' => 'Access your phone number',
    ];

    public function all(): Collection
    {
        $passportScopes = collect(Passport::$scopes)
            ->map(fn (string $description, string $id) => new Scope($id, $description));

        $oidcScopes = collect(self::OIDC_SCOPES)
            ->reject(fn (string $description, string $id) => $passportScopes->has($id))
            ->map(fn (string $description, string $id) => new Scope($id, $description));

        return $passportScopes->merge($oidcScopes)->values();
    }

    public function find(string $identifier): ?Scope
    {
        return $this->all()->first(fn (Scope $scope) => $scope->id === $identifier);
    }

    public function finalize(array $requested, string $grantType, ClientEntityInterface $client, ?string $userIdentifier = null): array
    {
        return array_values(array_filter(
            $requested,
            fn (Scope $scope) => $this->find($scope->id) instanceof Scope,
        ));
    }
}
