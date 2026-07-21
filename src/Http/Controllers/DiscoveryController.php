<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http\Controllers;

use Bambamboole\LaravelOidc\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Facades\Oidc;
use Bambamboole\LaravelOidc\Routing\Handler;
use Bambamboole\LaravelOidc\Scopes\Scope;
use Illuminate\Http\JsonResponse;
use Laravel\Passport\Passport;

class DiscoveryController
{
    public function __invoke(ScopeRepository $scopes): JsonResponse
    {
        $grantTypes = ['authorization_code', 'refresh_token', 'client_credentials'];

        if (Passport::$deviceCodeGrantEnabled) {
            $grantTypes[] = 'urn:ietf:params:oauth:grant-type:device_code';
        }

        if (config('oidc.token_exchange.enabled', true)) {
            $grantTypes[] = 'urn:ietf:params:oauth:grant-type:token-exchange';
        }

        $document = [
            'issuer' => Oidc::issuer(),
            'authorization_endpoint' => $this->endpoint(Handler::Authorize),
            'token_endpoint' => $this->endpoint(Handler::IssueToken),
            'jwks_uri' => $this->endpoint(Handler::Jwks),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => $grantTypes,
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => $scopes->all()
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

        if (Oidc::handlerConfig(Handler::Userinfo) !== false) {
            $document['userinfo_endpoint'] = $this->endpoint(Handler::Userinfo);
        }

        if (Oidc::handlerConfig(Handler::Logout) !== false) {
            $document['end_session_endpoint'] = $this->endpoint(Handler::Logout);
        }

        if (Oidc::handlerConfig(Handler::Introspect) !== false) {
            $document['introspection_endpoint'] = $this->endpoint(Handler::Introspect);
            $document['introspection_endpoint_auth_methods_supported'] = ['client_secret_basic', 'client_secret_post'];
        }

        if (Oidc::handlerConfig(Handler::Revoke) !== false) {
            $document['revocation_endpoint'] = $this->endpoint(Handler::Revoke);
            $document['revocation_endpoint_auth_methods_supported'] = ['client_secret_basic', 'client_secret_post'];
        }

        return response()->json($document)->header('Cache-Control', 'max-age=3600, public');
    }

    private function endpoint(Handler $handler): string
    {
        $path = parse_url(route($handler->value), PHP_URL_PATH);

        return rtrim(Oidc::issuer(), '/').($path ?? '');
    }
}
