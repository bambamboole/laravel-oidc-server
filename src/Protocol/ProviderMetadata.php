<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol;

use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AcrResolver;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\EndpointUrl;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
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
        private RealmResolver $realms,
        private EndpointUrl $endpoints,
        private AcrResolver $acr,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function document(): array
    {
        $realm = $this->realms->current();
        $grantTypes = ['authorization_code', 'refresh_token', 'client_credentials'];

        if ($realm->clients()->tokenExchange) {
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
            'claims_supported' => $realm->scopes()->claimsSupported,
            'acr_values_supported' => $this->acr->supported(),
            'claims_parameter_supported' => false,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'code_challenge_methods_supported' => ['S256'],
            'authorization_response_iss_parameter_supported' => true,
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
            $document['revocation_endpoint_auth_methods_supported'] = ['client_secret_basic', 'client_secret_post', 'none'];
        }

        if ($realm->clients()->dynamicRegistration) {
            $document['registration_endpoint'] = $this->endpoint('oidc.register');
        }

        return $document;
    }

    public function endpoint(string $routeName): string
    {
        return $this->endpoints->of($routeName);
    }
}
