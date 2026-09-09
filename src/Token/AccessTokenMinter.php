<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Token;

use Bambamboole\LaravelOidc\Server\Bridge\AccessTokenRepository;
use Bambamboole\LaravelOidc\Server\Bridge\Client as BridgeClient;
use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Scopes\BridgeScope;
use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\CryptKey;

class AccessTokenMinter
{
    public function __construct(
        private readonly AccessTokenRepository $tokens,
        private readonly SigningKeys $signingKeys,
    ) {}

    /**
     * @param  string[]  $scopeIds
     * @param  string[]  $audiences
     * @param  array<string, mixed>  $extraClaims
     */
    public function mint(
        ?string $userId,
        Client $client,
        array $scopeIds,
        DateInterval $ttl,
        array $audiences = [],
        array $extraClaims = [],
    ): OidcAccessToken {
        $bridgeClient = new BridgeClient(
            identifier: $client->client_id,
            name: $client->name,
            isConfidential: true,
            key: $client->getKey(),
        );
        $scopes = array_map(fn (string $id): BridgeScope => new BridgeScope($id), $scopeIds);

        $token = new OidcAccessToken($userId, $scopes, $bridgeClient);
        $token->setIdentifier(bin2hex(random_bytes(40)));
        $token->setExpiryDateTime((new DateTimeImmutable)->add($ttl));
        $token->setPrivateKey(new CryptKey($this->signingKeys->signingKey()->privateKey(), null, false));

        if ($audiences !== []) {
            $token->setAudience(...$audiences);
        }

        foreach ($extraClaims as $name => $value) {
            $token->addExtraClaim($name, $value);
        }

        $this->tokens->persistNewAccessToken($token);

        return $token;
    }
}
