<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\MintedAccessToken;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\ProtocolClaims;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use DateInterval;
use DateTimeImmutable;
use RuntimeException;

/**
 * Mints RFC 9068 (application/at+jwt) access tokens and persists the record
 * the guard, introspection and revocation read them back from. The `scopes`
 * array is kept next to the `scope` string for consumers that read it.
 */
final readonly class JwtAccessTokenMinter implements AccessTokenMinter
{
    public function __construct(
        private ClientRepository $clients,
        private SigningKeys $signingKeys,
        private IssuerResolver $issuer,
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

        $jti = bin2hex(random_bytes(40));
        $now = new DateTimeImmutable;
        $expiresAt = $now->add($ttl);
        $audience = $audiences !== [] ? $audiences : [$client->client_id];

        $config = $this->signingKeys->signingConfiguration();

        $builder = $config->builder()
            ->withHeader('typ', 'at+jwt')
            ->withHeader('kid', $this->signingKeys->signingKid())
            ->issuedBy($this->issuer->url())
            ->identifiedBy($jti)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($expiresAt)
            ->relatedTo($userId ?? $client->client_id)
            ->permittedFor(...$audience)
            ->withClaim('client_id', $client->client_id)
            ->withClaim('scope', implode(' ', $scopeIds))
            ->withClaim('scopes', $scopeIds);

        foreach ($extraClaims as $name => $value) {
            if (! ProtocolClaims::isAccessTokenReserved((string) $name)) {
                $builder = $builder->withClaim((string) $name, $value);
            }
        }

        if ($actor !== null) {
            $builder = $builder->withClaim('act', $actor);
        }

        $jwt = $builder->getToken($config->signer(), $config->signingKey())->toString();

        Token::query()->forceCreate([
            'realm_id' => Token::currentRealm(),
            'id' => $jti,
            'user_id' => $userId,
            'client_id' => $client->getKey(),
            'scopes' => $scopeIds,
            'revoked' => false,
            'expires_at' => $expiresAt,
        ]);

        return new MintedAccessToken(
            jwt: $jwt,
            jti: $jti,
            userId: $userId,
            clientId: $client->client_id,
            scopes: $scopeIds,
            audience: $audience,
            expiresAt: $expiresAt,
        );
    }
}
