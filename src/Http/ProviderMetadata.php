<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http;

use Bambamboole\LaravelOidc\Server\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Realm\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Illuminate\Support\Facades\Route;

/**
 * Builds the provider metadata document served both as the OIDC Discovery 1.0
 * document and as RFC 8414 authorization server metadata — RFC 8414 §2 allows
 * additional members, so the OIDC-specific fields are valid in both.
 */
final readonly class ProviderMetadata
{
    public function __construct(
        private ScopeRepository $scopes,
        private IssuerResolver $issuer,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function document(): array
    {
        $grantTypes = ['authorization_code', 'refresh_token', 'client_credentials'];

        if (config('oidc.token_exchange.enabled', true)) {
            $grantTypes[] = 'urn:ietf:params:oauth:grant-type:token-exchange';
        }

        $document = [
            'issuer' => $this->issuer->url(),
            'authorization_endpoint' => $this->endpoint('oidc.authorize'),
            'token_endpoint' => $this->endpoint('oidc.token'),
            'jwks_uri' => $this->endpoint('oidc.jwks'),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => $grantTypes,
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => $this->scopes->all()
                ->reject(fn (Scope $scope) => $scope->hidden)
                ->map(fn (Scope $scope) => $scope->id)
                ->values()
                ->all(),
            'claims_supported' => config('oidc.claims_supported'),
            'claims_parameter_supported' => false,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'code_challenge_methods_supported' => ['S256'],
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
        ];

        if (Route::has('oidc.userinfo')) {
            $document['userinfo_endpoint'] = $this->endpoint('oidc.userinfo');
        }

        if (Route::has('oidc.logout')) {
            $document['end_session_endpoint'] = $this->endpoint('oidc.logout');
        }

        if (Route::has('oidc.introspect')) {
            $document['introspection_endpoint'] = $this->endpoint('oidc.introspect');
            $document['introspection_endpoint_auth_methods_supported'] = ['client_secret_basic', 'client_secret_post'];
        }

        if (Route::has('oidc.revoke')) {
            $document['revocation_endpoint'] = $this->endpoint('oidc.revoke');
            $document['revocation_endpoint_auth_methods_supported'] = ['client_secret_basic', 'client_secret_post'];
        }

        if (Route::has('oidc.register')) {
            $document['registration_endpoint'] = $this->endpoint('oidc.register');
        }

        return $document;
    }

    public function endpoint(string $routeName): string
    {
        $path = parse_url(route($routeName), PHP_URL_PATH);

        return $this->origin().($path ?? '');
    }

    /**
     * Endpoint paths already carry the realm, so they are hung off the issuer's
     * origin rather than the issuer itself. Rebuilding from the issuer rather
     * than the request keeps a forwarded host out of the document.
     */
    private function origin(): string
    {
        $issuer = rtrim($this->issuer->url(), '/');
        $parts = parse_url($issuer);

        if (! isset($parts['scheme'], $parts['host'])) {
            return $issuer;
        }

        $port = isset($parts['port']) ? ':'.$parts['port'] : '';

        return $parts['scheme'].'://'.$parts['host'].$port;
    }
}
