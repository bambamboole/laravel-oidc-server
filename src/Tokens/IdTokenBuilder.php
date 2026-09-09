<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Authentication\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsAudience;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsRequest;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsResolver;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\ResolvesTokenUser;
use DateTimeImmutable;
use RuntimeException;

class IdTokenBuilder
{
    use ResolvesTokenUser;

    public function __construct(
        private readonly ClaimsResolver $claims,
        private readonly IssuerResolver $issuer,
        private readonly SigningKeys $signingKeys,
        private readonly RealmResolver $realms,
    ) {}

    public function build(IdTokenRequest $request): string
    {
        $config = $this->signingKeys->signingConfiguration();

        $clientId = $request->clientId;
        $nonce = $request->nonce;
        $authTime = $request->authTime;
        $sid = $request->sid;
        $amr = $request->amr;
        $now = new DateTimeImmutable;

        $builder = $config->builder()
            ->withHeader('kid', $this->signingKeys->signingKid())
            ->issuedBy($this->issuer->url())
            ->permittedFor($clientId)
            ->relatedTo($request->userId)
            ->issuedAt($now)
            ->expiresAt($now->modify('+'.$this->realms->current()->tokens()->idTokenLifetime.' seconds'))
            ->withClaim('azp', $clientId)
            ->withClaim('at_hash', $this->atHash($request->accessToken));

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
            $builder = $builder->withClaim('amr', $amr);

            $acr = AuthSessionState::deriveAcr($amr);
            if ($acr !== null) {
                $builder = $builder->withClaim('acr', $acr);
            }
        }

        foreach ($request->idTokenClaims as $name => $value) {
            if (! ProtocolClaims::isReserved($name)) {
                $builder = $builder->withClaim($name, $value);
            }
        }

        $user = $this->resolveUser($request->userId)
            ?? throw new RuntimeException('Unable to resolve the user for id_token issuance: '.$request->userId);

        $resolved = $this->claims->resolve(new ClaimsRequest(
            user: $user,
            audience: ClaimsAudience::IdToken,
            clientId: $clientId,
            scopes: $request->scopes,
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
