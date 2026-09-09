<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League\Repositories;

use Bambamboole\LaravelOidc\Server\Clients\Client as ClientModel;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository as ClientModelRepository;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ClientEntity;
use Illuminate\Contracts\Hashing\Hasher;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

class ClientRepository implements ClientRepositoryInterface
{
    public function __construct(
        protected ClientModelRepository $clients,
        protected Hasher $hasher,
    ) {}

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $record = $this->clients->findActive($clientIdentifier);

        return $record !== null ? $this->fromClientModel($record) : null;
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        $record = $this->clients->findActive($clientIdentifier);

        if ($record === null) {
            return false;
        }

        if (! $record->confidential()) {
            return $clientSecret === null || $clientSecret === '';
        }

        return $clientSecret !== null
            && $clientSecret !== ''
            && $this->hasher->check($clientSecret, (string) $record->getAttributes()['secret']);
    }

    public function getPersonalAccessClientEntity(?string $provider = null): ClientEntityInterface
    {
        return $this->fromClientModel($this->clients->personalAccessClient($provider));
    }

    protected function fromClientModel(ClientModel $model): ClientEntityInterface
    {
        return new ClientEntity(
            identifier: $model->client_id,
            name: $model->name,
            redirectUri: $model->redirect_uris,
            isConfidential: $model->confidential(),
            key: $model->getKey(),
            provider: $model->provider,
            grantTypes: $model->grant_types,
        );
    }
}
