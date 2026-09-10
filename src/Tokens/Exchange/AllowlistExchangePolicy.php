<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Exchange;

use Bambamboole\LaravelOidc\Server\Clients\AllowedAudiences;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;

class AllowlistExchangePolicy implements ExchangePolicy
{
    public function authorize(ExchangeRequest $request): ExchangeGrantResult
    {
        $claims = $request->subjectClaims;
        $subject = (string) ($claims['sub'] ?? '');
        if ($subject === '') {
            throw ExchangeDeniedException::invalidGrant('The subject token has no subject.');
        }

        $subjectAudience = $this->normalize($claims['aud'] ?? []);
        $subjectClientId = is_string($claims['client_id'] ?? null) ? $claims['client_id'] : null;
        $clientId = $request->client->client_id;

        if (! in_array($clientId, $subjectAudience, true) && $subjectClientId !== $clientId) {
            throw ExchangeDeniedException::accessDenied('The subject token was not issued to the requesting client.');
        }

        $allowed = $this->allowedAudiences($request->client);
        $audience = $request->requestedAudience;
        if ($audience === null || ! in_array($audience, $allowed, true)) {
            throw ExchangeDeniedException::invalidTarget('The requested audience is not permitted for this client.');
        }

        $subjectScopes = $this->scopeList($claims['scope'] ?? '');
        $requested = $request->requestedScopes ?? $subjectScopes;
        $widened = array_diff($requested, $subjectScopes);
        if ($widened !== []) {
            throw ExchangeDeniedException::invalidScope(array_values($widened));
        }

        return new ExchangeGrantResult(
            userId: $subject,
            scopes: array_values($requested),
            audience: [$audience],
            expiresAt: $request->subjectExpiresAt,
        );
    }

    /** @return string[] */
    private function allowedAudiences(Client $client): array
    {
        return AllowedAudiences::of($client);
    }

    /** @return string[] */
    private function normalize(mixed $aud): array
    {
        return array_values(array_filter(is_array($aud) ? $aud : [$aud], 'is_string'));
    }

    /** @return string[] */
    private function scopeList(mixed $scope): array
    {
        return is_string($scope) && $scope !== '' ? explode(' ', $scope) : [];
    }
}
