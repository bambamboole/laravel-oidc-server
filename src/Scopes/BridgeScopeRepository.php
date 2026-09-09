<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeRepository as ScopeRepositoryContract;
use Illuminate\Support\Collection;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

class BridgeScopeRepository implements ScopeRepositoryInterface
{
    public function __construct(
        protected readonly ClientRepository $clients,
        private readonly ScopeRepositoryContract $scopes,
    ) {}

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        if ($identifier === '*') {
            return new BridgeScope($identifier);
        }

        return $this->scopes->find($identifier) instanceof Scope ? new BridgeScope($identifier) : null;
    }

    /**
     * @param  array<int, ScopeEntityInterface>  $scopes
     * @return array<int, ScopeEntityInterface>
     */
    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        $entities = collect($scopes)
            ->unless(in_array($grantType, ['personal_access', 'client_credentials'], true),
                fn (Collection $scopes): Collection => $scopes->reject(
                    fn (ScopeEntityInterface $scope): bool => $scope->getIdentifier() === '*'
                )
            )
            ->when($this->clients->findActive($clientEntity->getIdentifier()),
                fn (Collection $scopes, Client $client): Collection => $scopes->filter(
                    fn (ScopeEntityInterface $scope): bool => $client->hasScope($scope->getIdentifier())
                )
            );

        $wildcard = $entities->contains(
            fn (ScopeEntityInterface $scope): bool => $scope->getIdentifier() === '*'
        );

        $candidates = $entities
            ->map(fn (ScopeEntityInterface $scope): ?Scope => $this->scopes->find($scope->getIdentifier()))
            ->filter()
            ->values()
            ->all();

        $finalized = collect($this->scopes->finalize($candidates, $grantType, $clientEntity, $userIdentifier))
            ->map(fn (Scope $scope): ScopeEntityInterface => new BridgeScope($scope->id));

        if ($wildcard) {
            $finalized->prepend(new BridgeScope('*'));
        }

        return $finalized->values()->all();
    }
}
