<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Token;

use Bambamboole\LaravelOidc\Server\Authentication\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Claims\ClaimsAudience;
use Bambamboole\LaravelOidc\Server\Claims\ClaimsRequest;
use Bambamboole\LaravelOidc\Server\Claims\ClaimsResolver;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Realm\IssuerResolver;
use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use RuntimeException;

class IdTokenBuilder
{
    use ResolvesTokenUser;

    public function __construct(
        private readonly ClaimsResolver $claims,
        private readonly IssuerResolver $issuer,
        private readonly SigningKeys $signingKeys,
    ) {}

    /**
     * @param  array<int, string>  $amr
     * @param  array<string, mixed>  $idTokenClaims
     */
    public function build(AccessTokenEntityInterface $accessToken, ?string $nonce, ?int $authTime, array $amr = [], array $idTokenClaims = [], ?string $sid = null): string
    {
        $config = $this->signingKeys->signingConfiguration();

        $clientId = $accessToken->getClient()->getIdentifier();
        $scopes = array_map(
            fn (ScopeEntityInterface $scope) => $scope->getIdentifier(),
            $accessToken->getScopes(),
        );
        $now = new DateTimeImmutable;

        $builder = $config->builder()
            ->withHeader('kid', $this->signingKeys->signingKid())
            ->issuedBy($this->issuer->url())
            ->permittedFor($clientId)
            ->relatedTo((string) $accessToken->getUserIdentifier())
            ->issuedAt($now)
            ->expiresAt($now->modify('+'.config('oidc.token_lifetimes.id_token').' seconds'))
            ->withClaim('azp', $clientId)
            ->withClaim('at_hash', $this->atHash($accessToken->toString()));

        if ($nonce !== null && $nonce !== '') {
            $builder = $builder->withClaim('nonce', $nonce);
        }

        if ($authTime !== null) {
            $builder = $builder->withClaim('auth_time', $authTime);
        }

        if ($sid !== null && $sid !== '') {
            $builder = $builder->withClaim('sid', $sid);
        }

        if ($amr !== []) {
            $amr = array_values($amr);
            $builder = $builder->withClaim('amr', $amr);

            $acr = AuthSessionState::deriveAcr($amr);
            if ($acr !== null) {
                $builder = $builder->withClaim('acr', $acr);
            }
        }

        foreach ($idTokenClaims as $name => $value) {
            if (! ProtocolClaims::isReserved($name)) {
                $builder = $builder->withClaim($name, $value);
            }
        }

        $user = $this->resolveUser((string) $accessToken->getUserIdentifier())
            ?? throw new RuntimeException(
                'Unable to resolve the user for id_token issuance: '.$accessToken->getUserIdentifier(),
            );

        $resolved = $this->claims->resolve(new ClaimsRequest(
            user: $user,
            audience: ClaimsAudience::IdToken,
            clientId: $clientId,
            scopes: array_values($scopes),
        ));

        foreach ($resolved as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder->getToken($config->signer(), $config->signingKey())->toString();
    }

    private function atHash(string $accessTokenJwt): string
    {
        $hash = substr(hash('sha256', $accessTokenJwt, true), 0, 16);

        return sodium_bin2base64($hash, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }
}
