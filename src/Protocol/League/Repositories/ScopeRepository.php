<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League\Repositories;

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ScopeEntity;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeGrant;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeRepository as ScopeRepositoryContract;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

class ScopeRepository implements ScopeRepositoryInterface
{
    public function __construct(
        private readonly ClientRepository $clients,
        private readonly ScopeRepositoryContract $scopes,
        private readonly ScopeGrant $grant,
    ) {}

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        if ($identifier === '*') {
            return new ScopeEntity($identifier);
        }

        return $this->scopes->find($identifier) instanceof Scope ? new ScopeEntity($identifier) : null;
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
        $ids = $this->grant->finalize(
            array_map(fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(), $scopes),
            $grantType,
            $this->clients->findActive($clientEntity->getIdentifier()),
            $userIdentifier,
        );

        return array_map(fn (string $id): ScopeEntityInterface => new ScopeEntity($id), $ids);
    }
}
