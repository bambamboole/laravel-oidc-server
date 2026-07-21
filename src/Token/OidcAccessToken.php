<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Token;

use Bambamboole\LaravelOidc\Auth\ProtocolClaims;
use Bambamboole\LaravelOidc\Issuer;
use DateTimeImmutable;
use Laravel\Passport\Bridge\AccessToken;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;

/**
 * Emits an RFC 9068 (application/at+jwt) access token. league's AccessTokenTrait::convertToJWT is
 * private and stops at a bare JWT (no iss, no typ, a non-standard `scopes` array); we re-use the
 * trait to redefine it. The legacy `scopes` array is retained because Passport's auth:api guard and
 * this package's userinfo read it — dropping it breaks authentication. toString() stays memoized:
 * league 9.4 + lcobucci 5.6 mint fresh microsecond iat/nbf per call, so the at_hash computed in
 * IdTokenBuilder must hash the identical string returned as access_token.
 */
class OidcAccessToken extends AccessToken
{
    use AccessTokenTrait;

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
        $scopeIds = array_map(
            fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $this->getScopes(),
        );
        $now = new DateTimeImmutable;

        $builder = $this->jwtConfiguration->builder()
            ->withHeader('typ', 'at+jwt')
            ->withHeader('kid', SigningKeys::signingKid())
            ->issuedBy(Issuer::url())
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
}
