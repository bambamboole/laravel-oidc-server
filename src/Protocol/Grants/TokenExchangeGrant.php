<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Grants;

use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Http\ScopeParameter;
use Bambamboole\LaravelOidc\Server\Protocol\TokenResponse;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\ExchangeDeniedException;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\TokenExchanger;
use Illuminate\Http\Request;

/**
 * RFC 8693. Only access tokens are accepted and issued, an exchange never
 * mints a refresh token, and delegation through an actor_token is not
 * offered: the `act` claim always names the exchanging client (§4.1).
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

        if ($request->has('actor_token') || $request->has('actor_token_type')) {
            throw OAuthServerException::invalidRequest('Delegation with an actor_token is not supported.');
        }

        $subjectToken = $request->input('subject_token');

        if (! is_string($subjectToken) || $subjectToken === '') {
            throw OAuthServerException::invalidRequest('The subject_token parameter is missing.');
        }

        try {
            $token = $this->exchanger->exchange(
                $subjectToken,
                $client,
                $this->target($request),
                ScopeParameter::parse($request->input('scope')),
                $this->realms->current()->tokens()->accessToken(),
                array_diff_key($request->request->all(), array_flip(self::RESERVED_PARAMETERS)),
            );
        } catch (ExchangeDeniedException $denied) {
            throw $this->toOAuthError($denied);
        }

        return new TokenResponse($token, extra: ['issued_token_type' => self::ACCESS_TOKEN_URN]);
    }

    /**
     * RFC 8693 §2.1: `audience` and `resource` both name the target the token
     * is requested for, `resource` as an absolute URI (RFC 8707 §2). Given
     * together they must agree.
     */
    private function target(Request $request): string
    {
        $audience = $this->parameter($request, 'audience');
        $resource = $this->parameter($request, 'resource');

        if ($resource !== null && ! $this->isAbsoluteUri($resource)) {
            throw OAuthServerException::invalidTarget('The resource parameter must be an absolute URI without a fragment.');
        }

        if ($audience !== null && $resource !== null && $audience !== $resource) {
            throw OAuthServerException::invalidTarget('The audience and resource parameters name different targets.');
        }

        return $audience ?? $resource ?? throw OAuthServerException::invalidRequest('The audience or resource parameter is missing.');
    }

    private function parameter(Request $request, string $name): ?string
    {
        $value = $request->input($name);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function isAbsoluteUri(string $uri): bool
    {
        $parts = parse_url($uri);

        return is_array($parts) && isset($parts['scheme']) && ! isset($parts['fragment']);
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
