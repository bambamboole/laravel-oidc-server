<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Responses;

use Bambamboole\LaravelOidc\Support\ResolvesRequestGrantType;
use Bambamboole\LaravelOidc\Token\IdTokenBuilder;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;

class IdTokenResponse extends BearerTokenResponse
{
    use ResolvesRequestGrantType;

    private const string EXCHANGE_URN = 'urn:ietf:params:oauth:grant-type:token-exchange';

    private const string ACCESS_TOKEN_URN = 'urn:ietf:params:oauth:token-type:access_token';

    private ?string $nonce = null;

    private ?int $authTime = null;

    /** @var list<string> */
    private array $amr = [];

    /** @var array<string, mixed> */
    private array $idTokenClaims = [];

    private ?string $sid = null;

    public function __construct(private readonly IdTokenBuilder $builder) {}

    public function setNonce(?string $nonce): void
    {
        $this->nonce = $nonce;
    }

    public function setAuthTime(?int $authTime): void
    {
        $this->authTime = $authTime;
    }

    /**
     * @param  list<string>  $amr
     */
    public function setAmr(array $amr): void
    {
        $this->amr = $amr;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function setIdTokenClaims(array $claims): void
    {
        $this->idTokenClaims = $claims;
    }

    public function setSid(?string $sid): void
    {
        $this->sid = $sid;
    }

    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        // Read-and-clear: this response type is resolved once and reused across
        // requests on long-lived workers (Octane), so nonce/auth_time/amr/
        // idTokenClaims/sid must never leak into a subsequent token issuance.
        $nonce = $this->nonce;
        $authTime = $this->authTime;
        $amr = $this->amr;
        $idTokenClaims = $this->idTokenClaims;
        $sid = $this->sid;
        $this->nonce = null;
        $this->authTime = null;
        $this->amr = [];
        $this->idTokenClaims = [];
        $this->sid = null;

        $scopes = array_map(
            fn (ScopeEntityInterface $scope) => $scope->getIdentifier(),
            $accessToken->getScopes(),
        );

        $grantType = $this->requestGrantType();
        $params = [];
        $isExchange = $grantType === self::EXCHANGE_URN;

        if (! $isExchange && in_array('openid', $scopes, true) && $accessToken->getUserIdentifier() !== null) {
            $params['id_token'] = $this->builder->build($accessToken, $nonce, $authTime, $amr, $idTokenClaims, $sid);
        }

        if ($isExchange) {
            $params['issued_token_type'] = self::ACCESS_TOKEN_URN;
            $params['scope'] = implode(' ', $scopes);
        }

        return $params;
    }
}
