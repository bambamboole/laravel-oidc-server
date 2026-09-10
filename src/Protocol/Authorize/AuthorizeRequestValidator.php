<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Authorize;

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Grants\AuthorizationCodeGrant;
use Bambamboole\LaravelOidc\Server\Protocol\Http\Pkce;
use Bambamboole\LaravelOidc\Server\Protocol\Http\RedirectUri;
use Bambamboole\LaravelOidc\Server\Protocol\Http\ScopeParameter;
use Bambamboole\LaravelOidc\Server\Scopes\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\SignedJwtParser;
use Illuminate\Http\Request;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Validator;

/**
 * OAuth 2.1 §4.1.1 / §4.1.2.1: the client and redirect URI are checked first
 * and never redirected to when wrong; every later failure is reported to the
 * validated redirect URI. PKCE with S256 is required of every client.
 *
 * OpenID Connect Core §3.1.2.1: parameters come from the query string on GET
 * and from the form body on POST, never both.
 */
final readonly class AuthorizeRequestValidator
{
    /** OpenID Connect Core §3.1.2.1. */
    private const array PROMPTS = ['none', 'login', 'consent', 'select_account'];

    /** OAuth 2.0 Multiple Response Type Encoding Practices §2.1. */
    private const array RESPONSE_MODES = ['query'];

    public function __construct(
        private ClientRepository $clients,
        private ScopeRepository $scopes,
        private SignedJwtParser $jwts,
        private IssuerResolver $issuer,
    ) {}

    public function validate(Request $request): AuthorizeRequest
    {
        $duplicates = $this->duplicatedParameters($request);

        foreach (['client_id', 'redirect_uri'] as $name) {
            if (in_array($name, $duplicates, true)) {
                throw OAuthServerException::invalidRequest("The {$name} parameter is included more than once.");
            }
        }

        $clientId = $this->parameter($request, 'client_id')
            ?? throw OAuthServerException::invalidRequest('The client_id parameter is missing.');

        $client = $this->clients->findActive($clientId)
            ?? throw OAuthServerException::invalidRequest('The client is unknown.');

        [$redirectUri, $redirectUriRequested] = $this->redirectUri($request, $client);
        $state = $this->parameter($request, 'state');

        if ($duplicates !== []) {
            throw OAuthServerException::invalidRequest("The {$duplicates[0]} parameter is included more than once.", $redirectUri, $state);
        }

        if (! $client->hasGrantType(AuthorizationCodeGrant::TYPE)) {
            throw OAuthServerException::unauthorizedClient('The client is not authorized to use the authorization code grant.', $redirectUri, $state);
        }

        if ($this->parameter($request, 'response_type') !== 'code') {
            throw OAuthServerException::unsupportedResponseType($redirectUri, $state);
        }

        $responseMode = $this->parameter($request, 'response_mode');

        if ($responseMode !== null && ! in_array($responseMode, self::RESPONSE_MODES, true)) {
            throw OAuthServerException::invalidRequest("The response_mode {$responseMode} is not supported.", $redirectUri, $state);
        }

        if ($this->parameter($request, 'request') !== null) {
            throw OAuthServerException::requestNotSupported($redirectUri, $state);
        }

        if ($this->parameter($request, 'request_uri') !== null) {
            throw OAuthServerException::requestUriNotSupported($redirectUri, $state);
        }

        $scopes = ScopeParameter::parse($this->parameter($request, 'scope')) ?? [];

        foreach ($scopes as $scope) {
            if ($scope !== '*' && ! $this->scopes->find($scope) instanceof Scope) {
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
            prompt: $this->prompt($request, $redirectUri, $state),
            maxAge: $this->maxAge($request, $redirectUri, $state),
            acrValues: $this->spaceSeparated($this->parameter($request, 'acr_values')),
            idTokenHintSubject: $this->idTokenHintSubject($request, $redirectUri, $state),
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

    /**
     * OpenID Connect Core §3.1.2.1: `none` demands that nothing interactive
     * happens, so it cannot be combined with a value that asks for interaction.
     *
     * @return list<string>
     */
    private function prompt(Request $request, string $redirectUri, ?string $state): array
    {
        $prompt = array_values(array_unique($this->spaceSeparated($this->parameter($request, 'prompt'))));

        foreach ($prompt as $value) {
            if (! in_array($value, self::PROMPTS, true)) {
                throw OAuthServerException::invalidRequest("The prompt value {$value} is not supported.", $redirectUri, $state);
            }
        }

        if (in_array('none', $prompt, true) && count($prompt) > 1) {
            throw OAuthServerException::invalidRequest('The prompt value none cannot be combined with other values.', $redirectUri, $state);
        }

        return $prompt;
    }

    private function maxAge(Request $request, string $redirectUri, ?string $state): ?int
    {
        $maxAge = $this->parameter($request, 'max_age');

        if ($maxAge === null) {
            return null;
        }

        if (! ctype_digit($maxAge)) {
            throw OAuthServerException::invalidRequest('The max_age parameter must be a non-negative integer.', $redirectUri, $state);
        }

        return (int) $maxAge;
    }

    /**
     * OpenID Connect Core §3.1.2.1: a hint that does not verify against this
     * realm is a malformed request; the subject of one that does is compared
     * with the current session by the controller.
     */
    private function idTokenHintSubject(Request $request, string $redirectUri, ?string $state): ?string
    {
        $hint = $this->parameter($request, 'id_token_hint');

        if ($hint === null) {
            return null;
        }

        $token = $this->jwts->parse($hint);

        if (! $token instanceof Plain || ! (new Validator)->validate($token, new IssuedBy($this->issuer->url()))) {
            throw OAuthServerException::invalidRequest('The id_token_hint could not be verified.', $redirectUri, $state);
        }

        $subject = $token->claims()->get('sub');

        return is_string($subject) && $subject !== ''
            ? $subject
            : throw OAuthServerException::invalidRequest('The id_token_hint carries no subject.', $redirectUri, $state);
    }

    /**
     * OAuth 2.1 §4.1.1 / RFC 6749 §3.1: a parameter included more than once
     * invalidates the request. PHP keeps only the last value, so the raw
     * query string (GET) or form body (POST) is inspected.
     *
     * @return list<string>
     */
    private function duplicatedParameters(Request $request): array
    {
        $raw = $request->isMethod('POST')
            ? (string) $request->getContent()
            : (string) $request->server('QUERY_STRING', '');

        $names = [];

        foreach (explode('&', $raw) as $pair) {
            if ($pair !== '') {
                $names[] = urldecode(explode('=', $pair, 2)[0]);
            }
        }

        return array_keys(array_filter(array_count_values($names), fn (int $count): bool => $count > 1));
    }

    /** @return list<string> */
    private function spaceSeparated(?string $value): array
    {
        return array_values(array_filter(explode(' ', $value ?? ''), fn (string $item): bool => $item !== ''));
    }

    private function parameter(Request $request, string $name): ?string
    {
        $value = $request->isMethod('POST') ? $request->post($name) : $request->query($name);

        if (! is_scalar($value)) {
            return null;
        }

        $value = trim((string) $value);

        return $value === '' ? null : $value;
    }
}
