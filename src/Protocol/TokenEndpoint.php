<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol;

use Bambamboole\LaravelOidc\Server\Protocol\Clients\ClientAuthenticator;
use Bambamboole\LaravelOidc\Server\Protocol\Grants\Grant;
use Illuminate\Http\Request;

/**
 * RFC 6749 §3.2: dispatches a token request to the grant named by grant_type
 * after authenticating the client for it.
 */
final readonly class TokenEndpoint
{
    /** @param  list<Grant>  $grants */
    public function __construct(
        private ClientAuthenticator $clients,
        private array $grants,
    ) {}

    public function issue(Request $request): TokenResponse
    {
        $grantType = $request->input('grant_type');

        if (! is_string($grantType) || $grantType === '') {
            throw OAuthServerException::invalidRequest('The grant_type parameter is missing.');
        }

        $grant = $this->grant($grantType) ?? throw OAuthServerException::unsupportedGrantType();

        $client = $this->clients->authenticate($request, $grant->type());

        return $grant->handle($client, $request);
    }

    private function grant(string $type): ?Grant
    {
        foreach ($this->grants as $grant) {
            if ($grant->type() === $type) {
                return $grant;
            }
        }

        return null;
    }
}
