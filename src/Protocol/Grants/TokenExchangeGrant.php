<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Grants;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Protocol\Http\ScopeParameter;
use Bambamboole\LaravelOidc\Server\Protocol\TokenResponse;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\ExchangeDeniedException;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\TokenExchanger;
use Illuminate\Http\Request;

/**
 * RFC 8693. Only access tokens are accepted and issued, and an exchange never
 * mints a refresh token.
 */
final readonly class TokenExchangeGrant implements Grant
{
    public const string TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';

    private const string ACCESS_TOKEN_URN = 'urn:ietf:params:oauth:token-type:access_token';

    private const array RESERVED_PARAMETERS = [
        'grant_type', 'client_id', 'client_secret', 'subject_token', 'subject_token_type',
        'requested_token_type', 'audience', 'scope', 'resource', 'actor_token', 'actor_token_type',
    ];

    public function __construct(
        private TokenExchanger $exchanger,
        private FirstPartyClientConfig $firstPartyClients,
        private RealmResolver $realms,
    ) {}

    public function type(): string
    {
        return self::TYPE;
    }

    public function handle(Client $client, Request $request): TokenResponse
    {
        if (! $client->confidential() && ! $this->firstPartyClients->isTrusted($client->client_id)) {
            throw OAuthServerException::invalidClient();
        }

        if ($request->input('subject_token_type') !== self::ACCESS_TOKEN_URN) {
            throw OAuthServerException::invalidRequest('Only access_token subject tokens are supported.');
        }

        if ($request->input('requested_token_type', self::ACCESS_TOKEN_URN) !== self::ACCESS_TOKEN_URN) {
            throw OAuthServerException::invalidRequest('Only access_token may be requested.');
        }

        $subjectToken = $request->input('subject_token');

        if (! is_string($subjectToken) || $subjectToken === '') {
            throw OAuthServerException::invalidRequest('The subject_token parameter is missing.');
        }

        $audience = $request->input('audience');

        if (! is_string($audience) || $audience === '') {
            throw OAuthServerException::invalidRequest('The audience parameter is missing.');
        }

        try {
            $token = $this->exchanger->exchange(
                $subjectToken,
                $client,
                $audience,
                ScopeParameter::parse($request->input('scope')),
                $this->realms->current()->tokens()->accessToken(),
                array_diff_key($request->request->all(), array_flip(self::RESERVED_PARAMETERS)),
            );
        } catch (ExchangeDeniedException $denied) {
            throw $this->toOAuthError($denied);
        }

        return new TokenResponse($token, extra: [
            'issued_token_type' => self::ACCESS_TOKEN_URN,
            'scope' => implode(' ', $token->scopes),
        ]);
    }

    private function toOAuthError(ExchangeDeniedException $denied): OAuthServerException
    {
        return match ($denied->error) {
            'invalid_grant' => OAuthServerException::invalidGrant($denied->getMessage()),
            'access_denied' => OAuthServerException::accessDenied($denied->getMessage()),
            'invalid_scope' => OAuthServerException::invalidScope($denied->getMessage()),
            default => OAuthServerException::invalidTarget($denied->getMessage()),
        };
    }
}
