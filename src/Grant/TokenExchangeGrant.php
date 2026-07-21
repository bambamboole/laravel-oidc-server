<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Grant;

use Bambamboole\LaravelOidc\Exchange\TokenExchanger;
use DateInterval;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenExchangeGrant extends AbstractGrant
{
    private const string GRANT_URN = 'urn:ietf:params:oauth:grant-type:token-exchange';

    private const string ACCESS_TOKEN_URN = 'urn:ietf:params:oauth:token-type:access_token';

    public function __construct(
        private readonly TokenExchanger $exchanger,
    ) {}

    public function getIdentifier(): string
    {
        return self::GRANT_URN;
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        $client = $this->validateClient($request);

        if (! $client->isConfidential()) {
            throw OAuthServerException::invalidClient($request);
        }

        if ($this->getRequestParameter('subject_token_type', $request) !== self::ACCESS_TOKEN_URN) {
            throw OAuthServerException::invalidRequest('subject_token_type', 'Only access_token subject tokens are supported.');
        }

        if ($this->getRequestParameter('requested_token_type', $request, self::ACCESS_TOKEN_URN) !== self::ACCESS_TOKEN_URN) {
            throw OAuthServerException::invalidRequest('requested_token_type', 'Only access_token may be requested.');
        }

        $subjectTokenJwt = $this->getRequestParameter('subject_token', $request);
        if ($subjectTokenJwt === null) {
            throw OAuthServerException::invalidRequest('subject_token');
        }

        $audience = $this->getRequestParameter('audience', $request);
        if ($audience === null) {
            throw OAuthServerException::invalidRequest('audience');
        }

        $passportClient = Passport::client()->newQuery()->find($client->getIdentifier());
        if ($passportClient === null) {
            throw OAuthServerException::invalidClient($request);
        }

        $accessToken = $this->exchanger->exchange(
            $subjectTokenJwt,
            $passportClient,
            $audience,
            $this->scopeParam($request),
            $accessTokenTTL,
        );

        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $responseType->setAccessToken($accessToken);

        // Exchange must never mint a refresh token; issueRefreshToken is deliberately never called.
        return $responseType;
    }

    /** @return string[]|null */
    private function scopeParam(ServerRequestInterface $request): ?array
    {
        $scope = $this->getRequestParameter('scope', $request);

        return $scope === null ? null : array_values(array_filter(explode(' ', $scope)));
    }
}
