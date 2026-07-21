<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Exchange;

use Bambamboole\LaravelOidc\Contracts\ExchangePolicy;
use Laravel\Passport\Client;
use League\OAuth2\Server\Exception\OAuthServerException;

class DefaultExchangePolicy implements ExchangePolicy
{
    /**
     * League's built-in factories use error codes 2-14; this is chosen well outside that range
     * so it never collides with an upstream code the client might switch on.
     */
    private const INVALID_TARGET_ERROR_CODE = 900;

    public function authorize(ExchangeRequest $request): ExchangeGrantResult
    {
        $claims = $request->subjectClaims;
        $subject = (string) ($claims['sub'] ?? '');
        if ($subject === '') {
            throw OAuthServerException::invalidGrant('The subject token has no subject.');
        }

        $subjectAudience = $this->normalize($claims['aud'] ?? []);
        $subjectClientId = is_string($claims['client_id'] ?? null) ? $claims['client_id'] : null;
        $clientId = (string) $request->client->getKey();

        if (! in_array($clientId, $subjectAudience, true) && $subjectClientId !== $clientId) {
            throw OAuthServerException::accessDenied('The subject token was not issued to the requesting client.');
        }

        $allowed = $this->allowedAudiences($request->client);
        $audience = $request->requestedAudience;
        if ($audience === null || ! in_array($audience, $allowed, true)) {
            throw new OAuthServerException(
                'The requested audience is not permitted for this client.', self::INVALID_TARGET_ERROR_CODE, 'invalid_target', 400,
            );
        }

        $subjectScopes = $this->scopeList($claims['scope'] ?? '');
        $requested = $request->requestedScopes ?? $subjectScopes;
        $widened = array_diff($requested, $subjectScopes);
        if ($widened !== []) {
            throw OAuthServerException::invalidScope(implode(' ', $widened));
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
        $raw = $client->getRawOriginal('allowed_exchange_audiences');
        $decoded = is_string($raw) ? json_decode($raw, true) : null;

        return is_array($decoded) ? array_values(array_filter($decoded, 'is_string')) : [];
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
