<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Token;

use DateInterval;
use DateTimeImmutable;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Bridge\Client as BridgeClient;
use Laravel\Passport\Bridge\Scope as BridgeScope;
use Laravel\Passport\Client;
use League\OAuth2\Server\CryptKey;

class AccessTokenMinter
{
    public function __construct(private readonly AccessTokenRepository $tokens) {}

    /**
     * @param  string[]  $scopeIds
     * @param  string[]  $audiences
     */
    public function mint(?string $userId, Client $client, array $scopeIds, DateInterval $ttl, array $audiences = []): OidcAccessToken
    {
        $bridgeClient = new BridgeClient((string) $client->getKey(), (string) $client->getAttribute('name'), [], true);
        $scopes = array_map(fn (string $id): BridgeScope => new BridgeScope($id), $scopeIds);

        $token = new OidcAccessToken($userId, $scopes, $bridgeClient);
        $token->setIdentifier(bin2hex(random_bytes(40)));
        $token->setExpiryDateTime((new DateTimeImmutable)->add($ttl));
        $token->setPrivateKey(new CryptKey(SigningKeys::privateKey(), null, false));

        if ($audiences !== []) {
            $token->setAudience(...$audiences);
        }

        $this->tokens->persistNewAccessToken($token);

        return $token;
    }
}
