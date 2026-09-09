<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League;

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\AccessTokenEntity;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ClientEntity as BridgeClient;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ScopeEntity;
use Bambamboole\LaravelOidc\Server\Protocol\League\Repositories\AccessTokenRepository;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\MintedAccessToken;
use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\CryptKey;
use RuntimeException;

class LeagueAccessTokenMinter implements AccessTokenMinter
{
    public function __construct(
        private readonly AccessTokenRepository $tokens,
        private readonly SigningKeys $signingKeys,
        private readonly ClientRepository $clients,
    ) {}

    public function mint(
        ?string $userId,
        string $clientId,
        array $scopeIds,
        DateInterval $ttl,
        array $audiences = [],
        array $extraClaims = [],
        ?array $actor = null,
    ): MintedAccessToken {
        $client = $this->clients->findActive($clientId)
            ?? throw new RuntimeException("Cannot mint an access token for the unknown or revoked client [{$clientId}].");

        $bridgeClient = new BridgeClient(
            identifier: $client->client_id,
            name: $client->name,
            isConfidential: true,
            key: $client->getKey(),
        );

        $scopes = array_map(fn (string $id): ScopeEntity => new ScopeEntity($id), $scopeIds);

        $token = new AccessTokenEntity($userId, $scopes, $bridgeClient);
        $token->setIdentifier(bin2hex(random_bytes(40)));
        $token->setExpiryDateTime((new DateTimeImmutable)->add($ttl));
        $token->setPrivateKey(new CryptKey($this->signingKeys->signingKey()->privateKey(), null, false));

        if ($audiences !== []) {
            $token->setAudience(...$audiences);
        }

        foreach ($extraClaims as $name => $value) {
            $token->addExtraClaim($name, $value);
        }

        if ($actor !== null) {
            $token->setActor($actor);
        }

        $this->tokens->persistNewAccessToken($token);

        return new MintedAccessToken(
            jwt: $token->toString(),
            jti: $token->getIdentifier(),
            userId: $userId,
            clientId: $client->client_id,
            scopes: $token->scopeIdentifiers(),
            audience: $audiences !== [] ? $audiences : [$client->client_id],
            expiresAt: $token->getExpiryDateTime(),
        );
    }
}
