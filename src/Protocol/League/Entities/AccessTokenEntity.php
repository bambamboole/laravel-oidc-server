<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League\Entities;

use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\MintedAccessToken;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\ProtocolClaims;
use DateTimeImmutable;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

/**
 * The access token league mints, serialized as an RFC 9068 (application/at+jwt)
 * token. league's AccessTokenTrait::convertToJWT is private and stops at a bare
 * JWT (no iss, no typ, a non-standard `scopes` array), so it is redefined here.
 * The legacy `scopes` array is retained for consumers that still read it; the
 * package's own `auth:oidc` guard and userinfo endpoint read scopes off the
 * persisted token record instead. toString() stays memoized: league 9.4 +
 * lcobucci 5.6 mint fresh microsecond iat/nbf per call, so the at_hash computed
 * in IdTokenBuilder must hash the identical string returned as access_token.
 */
class AccessTokenEntity implements AccessTokenEntityInterface
{
    use AccessTokenTrait, EntityTrait, TokenEntityTrait;

    /** @param  array<int, ScopeEntityInterface>  $scopes */
    public function __construct(?string $userIdentifier, array $scopes, ClientEntityInterface $client)
    {
        if ($userIdentifier !== null) {
            $this->setUserIdentifier($userIdentifier);
        }

        foreach ($scopes as $scope) {
            $this->addScope($scope);
        }

        $this->setClient($client);
    }

    /**
     * @return list<string>
     */
    public function scopeIdentifiers(): array
    {
        return array_values(array_map(
            fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $this->getScopes(),
        ));
    }

    private ?string $serialized = null;

    /** @var string[] */
    private array $audience = [];

    /** @var array<string, mixed> */
    private array $extra = [];

    /** @var array<string, mixed>|null */
    private ?array $actor = null;

    public function setAudience(string ...$audience): void
    {
        $this->audience = $audience;
    }

    public function addExtraClaim(string $name, mixed $value): void
    {
        if (! ProtocolClaims::isAccessTokenReserved($name)) {
            $this->extra[$name] = $value;
        }
    }

    /** @param array<string, mixed> $actor */
    public function setActor(array $actor): void
    {
        $this->actor = $actor;
    }

    public function convertToJWT(): Token
    {
        $this->initJwtConfiguration();

        $clientId = $this->getClient()->getIdentifier();
        $audience = $this->audience !== [] ? $this->audience : [$clientId];
        $scopeIds = $this->scopeIdentifiers();
        $now = new DateTimeImmutable;

        $builder = $this->jwtConfiguration->builder()
            ->withHeader('typ', 'at+jwt')
            ->withHeader('kid', app(SigningKeys::class)->signingKid())
            ->issuedBy(app(IssuerResolver::class)->url())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo($this->getSubjectIdentifier())
            ->withClaim('client_id', $clientId)
            ->withClaim('scope', implode(' ', $scopeIds))
            ->withClaim('scopes', $scopeIds);

        foreach ($audience as $aud) {
            $builder = $builder->permittedFor($aud);
        }

        foreach ($this->extra as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        if ($this->actor !== null) {
            $builder = $builder->withClaim('act', $this->actor);
        }

        return $builder->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());
    }

    public function toString(): string
    {
        return $this->serialized ??= $this->convertToJWT()->toString();
    }

    /**
     * Wraps an already-minted token so league can hand it out through its
     * response types. The serialized form is pinned: re-signing would change
     * iat/nbf and break the persisted record the JWT was issued against.
     */
    public static function fromMinted(MintedAccessToken $minted, ClientEntityInterface $client): self
    {
        $entity = new self(
            $minted->userId,
            array_map(fn (string $id): ScopeEntity => new ScopeEntity($id), $minted->scopes),
            $client,
        );
        $entity->setIdentifier($minted->jti);
        $entity->setExpiryDateTime($minted->expiresAt);
        $entity->setAudience(...$minted->audience);
        $entity->serialized = $minted->jwt;

        return $entity;
    }
}
