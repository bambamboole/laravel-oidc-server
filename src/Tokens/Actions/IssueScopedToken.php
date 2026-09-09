<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Actions;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Shared\Sessions\SessionTokenProvider;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\IssuedToken;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\TokenExchanger;
use RuntimeException;

/**
 * Exchange the current user's session root token for an access token scoped
 * to one audience, on behalf of the first-party client (RFC 8693).
 */
final class IssueScopedToken
{
    public function __construct(
        private readonly SessionTokenProvider $sessionTokens,
        private readonly FirstPartyClientConfig $firstParty,
        private readonly TokenExchanger $exchanger,
    ) {}

    /**
     * @param  string[]  $scopes
     */
    public function __invoke(string $audience, array $scopes): IssuedToken
    {
        $subject = $this->sessionTokens->currentToken();

        if ($subject === null) {
            throw new RuntimeException('No session token is available for the current user.');
        }

        $client = Client::query()->find($this->firstParty->clientId());

        if ($client === null) {
            throw new RuntimeException('The oidc.first_party.client_id is not configured or does not exist.');
        }

        return IssuedToken::fromMinted($this->exchanger->exchange($subject, $client, $audience, $scopes), $audience);
    }
}
