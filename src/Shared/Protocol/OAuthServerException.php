<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Protocol;

use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;

/**
 * An OAuth error, rendered as the HTTP response the protocol prescribes: a
 * redirect back to the client where one is validated (RFC 6749 §4.1.2.1), a
 * JSON body otherwise (§5.2, RFC 6750 §3). Every redirect carries the RFC
 * 9207 §2 `iss` parameter, error responses included. Extends
 * HttpResponseException so Laravel renders it without reporting it.
 */
final class OAuthServerException extends HttpResponseException
{
    /**
     * @param  string|null  $error  null for the RFC 6750 §3.1 challenge to a request that presented no credentials, which carries no error code
     * @param  array<string, string>  $headers
     */
    private function __construct(
        public readonly ?string $error,
        public readonly string $description,
        public readonly int $status,
        ?string $redirectUri = null,
        ?string $state = null,
        array $headers = [],
    ) {
        $headers = ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache', ...$headers];

        parent::__construct(match (true) {
            $redirectUri !== null => new RedirectResponse($this->appendQuery($redirectUri, array_filter([
                'error' => $error,
                'error_description' => $description,
                'state' => $state,
                'iss' => app(IssuerResolver::class)->url(),
            ], fn (?string $value): bool => $value !== null))),
            $error === null => new Response('', $status, $headers),
            default => new JsonResponse(['error' => $error, 'error_description' => $description], $status, $headers),
        });

        $this->message = $description;
    }

    public static function invalidRequest(string $description, ?string $redirectUri = null, ?string $state = null): self
    {
        return new self('invalid_request', $description, 400, $redirectUri, $state);
    }

    /** RFC 6749 §5.2: the challenge names the realm the client failed to authenticate against. */
    public static function invalidClient(string $description = 'Client authentication failed.'): self
    {
        return new self('invalid_client', $description, 401, headers: ['WWW-Authenticate' => 'Basic realm="'.self::realm().'"']);
    }

    /**
     * RFC 6750 §3.1: a request without any bearer token is challenged without
     * an error code, and without a body to describe one.
     */
    public static function bearerRequired(): self
    {
        return new self(null, 'A bearer token is required.', 401, headers: ['WWW-Authenticate' => self::bearerChallenge(null)]);
    }

    /** RFC 6750 §3.1. */
    public static function invalidToken(string $description = 'The access token is invalid.'): self
    {
        return new self('invalid_token', $description, 401, headers: ['WWW-Authenticate' => self::bearerChallenge('invalid_token')]);
    }

    /** RFC 6750 §3.1. */
    public static function insufficientScope(string $description = 'The access token does not grant the required scope.'): self
    {
        return new self('insufficient_scope', $description, 403, headers: ['WWW-Authenticate' => self::bearerChallenge('insufficient_scope')]);
    }

    public static function invalidGrant(string $description): self
    {
        return new self('invalid_grant', $description, 400);
    }

    public static function unauthorizedClient(string $description, ?string $redirectUri = null, ?string $state = null): self
    {
        return new self('unauthorized_client', $description, 400, $redirectUri, $state);
    }

    public static function unsupportedGrantType(): self
    {
        return new self('unsupported_grant_type', 'The authorization grant type is not supported by the authorization server.', 400);
    }

    public static function unsupportedResponseType(string $redirectUri, ?string $state): self
    {
        return new self('unsupported_response_type', 'The authorization server does not support obtaining an authorization code using this method.', 400, $redirectUri, $state);
    }

    public static function invalidScope(string $scope, ?string $redirectUri = null, ?string $state = null): self
    {
        return new self('invalid_scope', "The requested scope is invalid, unknown, or malformed: {$scope}.", 400, $redirectUri, $state);
    }

    public static function accessDenied(?string $description = null, ?string $redirectUri = null, ?string $state = null): self
    {
        return new self('access_denied', $description ?? 'The resource owner or authorization server denied the request.', 400, $redirectUri, $state);
    }

    /** RFC 8707 §2 / RFC 8693 §2.2.2. */
    public static function invalidTarget(string $description, ?string $redirectUri = null, ?string $state = null): self
    {
        return new self('invalid_target', $description, 400, $redirectUri, $state);
    }

    /** OpenID Connect Core §3.1.2.6. */
    public static function loginRequired(string $redirectUri, ?string $state): self
    {
        return new self('login_required', 'The authorization server requires end-user authentication.', 401, $redirectUri, $state);
    }

    /** OpenID Connect Core §3.1.2.6. */
    public static function consentRequired(string $redirectUri, ?string $state): self
    {
        return new self('consent_required', 'The authorization server requires end-user consent.', 401, $redirectUri, $state);
    }

    /** OpenID Connect Core §3.1.2.6 / §6: the request parameter is not supported. */
    public static function requestNotSupported(string $redirectUri, ?string $state): self
    {
        return new self('request_not_supported', 'The authorization server does not support the request parameter.', 400, $redirectUri, $state);
    }

    /** OpenID Connect Core §3.1.2.6 / §6: the request_uri parameter is not supported. */
    public static function requestUriNotSupported(string $redirectUri, ?string $state): self
    {
        return new self('request_uri_not_supported', 'The authorization server does not support the request_uri parameter.', 400, $redirectUri, $state);
    }

    public static function serverError(string $description): self
    {
        return new self('server_error', $description, 500);
    }

    /**
     * RFC 6750 §3 challenge; RFC 9728 §5.1 points the client at the realm's
     * protected resource metadata where that endpoint is registered.
     */
    private static function bearerChallenge(?string $error): string
    {
        $parameters = array_filter([
            'realm' => self::realm(),
            'error' => $error,
            'resource_metadata' => Route::has('oidc.protected-resource') ? app(EndpointUrl::class)->of('oidc.protected-resource') : null,
        ], fn (?string $value): bool => $value !== null);

        return 'Bearer '.implode(', ', array_map(
            fn (string $name, string $value): string => $name.'="'.$value.'"',
            array_keys($parameters),
            $parameters,
        ));
    }

    private static function realm(): string
    {
        return app(RealmResolver::class)->current()->id();
    }

    /** @param  array<string, string>  $parameters */
    private function appendQuery(string $uri, array $parameters): string
    {
        return $uri.(str_contains($uri, '?') ? '&' : '?').http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }
}
