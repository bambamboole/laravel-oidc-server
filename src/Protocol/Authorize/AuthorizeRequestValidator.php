<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Authorize;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Protocol\Grants\AuthorizationCodeGrant;
use Bambamboole\LaravelOidc\Server\Protocol\Http\Pkce;
use Bambamboole\LaravelOidc\Server\Protocol\Http\RedirectUri;
use Bambamboole\LaravelOidc\Server\Protocol\Http\ScopeParameter;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Illuminate\Http\Request;

/**
 * OAuth 2.1 §4.1.1 / §4.1.2.1: the client and redirect URI are checked first
 * and never redirected to when wrong; every later failure is reported to the
 * validated redirect URI. PKCE with S256 is required of every client.
 */
final readonly class AuthorizeRequestValidator
{
    public function __construct(
        private ClientRepository $clients,
        private ScopeRepository $scopes,
    ) {}

    public function validate(Request $request): AuthorizeRequest
    {
        $clientId = $this->parameter($request, 'client_id')
            ?? throw OAuthServerException::invalidRequest('The client_id parameter is missing.');

        $client = $this->clients->findActive($clientId)
            ?? throw OAuthServerException::invalidClient('The client is unknown.');

        [$redirectUri, $redirectUriRequested] = $this->redirectUri($request, $client);
        $state = $this->parameter($request, 'state');

        if (! $client->hasGrantType(AuthorizationCodeGrant::TYPE)) {
            throw OAuthServerException::unauthorizedClient('The client is not authorized to use the authorization code grant.', $redirectUri, $state);
        }

        if ($this->parameter($request, 'response_type') !== 'code') {
            throw OAuthServerException::unsupportedResponseType($redirectUri, $state);
        }

        $scopes = ScopeParameter::parse($request->query('scope')) ?? [];

        foreach ($scopes as $scope) {
            if ($scope !== '*' && $this->scopes->find($scope) === null) {
                throw OAuthServerException::invalidScope($scope, $redirectUri, $state);
            }
        }

        $codeChallenge = $this->parameter($request, 'code_challenge')
            ?? throw OAuthServerException::invalidRequest('The code_challenge parameter is required.', $redirectUri, $state);

        if ($this->parameter($request, 'code_challenge_method') !== Pkce::METHOD) {
            throw OAuthServerException::invalidRequest('The code_challenge_method must be S256.', $redirectUri, $state);
        }

        if (! Pkce::isWellFormed($codeChallenge)) {
            throw OAuthServerException::invalidRequest('The code_challenge must follow RFC 7636 §4.2.', $redirectUri, $state);
        }

        return new AuthorizeRequest(
            clientId: $client->client_id,
            redirectUri: $redirectUri,
            redirectUriRequested: $redirectUriRequested,
            scopes: $scopes,
            state: $state,
            codeChallenge: $codeChallenge,
            codeChallengeMethod: Pkce::METHOD,
            nonce: $this->parameter($request, 'nonce'),
        );
    }

    /**
     * @return array{string, bool}
     */
    private function redirectUri(Request $request, Client $client): array
    {
        $registered = array_values(array_filter($client->redirect_uris ?? [], is_string(...)));
        $requested = $this->parameter($request, 'redirect_uri');

        if ($requested !== null) {
            if (! RedirectUri::matches($requested, $registered)) {
                throw OAuthServerException::invalidRequest('The redirect_uri is not registered for this client.');
            }

            return [$requested, true];
        }

        if (count($registered) !== 1) {
            throw OAuthServerException::invalidRequest('The redirect_uri parameter is required.');
        }

        return [$registered[0], false];
    }

    private function parameter(Request $request, string $name): ?string
    {
        $value = $request->query($name);

        if (! is_scalar($value)) {
            return null;
        }

        $value = trim((string) $value);

        return $value === '' ? null : $value;
    }
}
