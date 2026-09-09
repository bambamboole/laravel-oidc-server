<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Exchange;

use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeGrant;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\MintedAccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Guard\ResolvesTokenUser;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Tokens\Pipeline\TokenExchangeEvent;
use Bambamboole\LaravelOidc\Server\Tokens\TokenInspector;
use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;

class TokenExchanger
{
    use ResolvesTokenUser;

    private const string GRANT_URN = 'urn:ietf:params:oauth:grant-type:token-exchange';

    public function __construct(
        private readonly ExchangePolicy $policy,
        private readonly TokenInspector $inspector,
        private readonly AccessTokenMinter $minter,
        private readonly RealmResolver $realms,
        private readonly ScopeGrant $scopes,
        private readonly AccessTokenPipeline $pipeline,
        private readonly Auditor $auditor,
    ) {}

    /**
     * @param  string[]|null  $scopes
     * @param  array<string, mixed>  $parameters
     */
    public function exchange(
        string $subjectToken,
        Client $requestingClient,
        string $audience,
        ?array $scopes = null,
        ?DateInterval $accessTokenTTL = null,
        array $parameters = [],
    ): MintedAccessToken {
        $parsed = $this->inspector->parse($subjectToken);
        $dbToken = $parsed !== null ? $this->inspector->tokenForParsed($parsed) : null;

        if ($parsed === null || $dbToken === null || (bool) $dbToken->getAttribute('revoked')) {
            $this->deny($requestingClient, 'subject_token_invalid', 'The subject token is invalid.');
        }

        if (((string) ($dbToken->getAttribute('user_id') ?? '')) === '') {
            $this->deny($requestingClient, 'subject_token_userless', 'The subject token must be bound to a user.');
        }

        $claims = $parsed->claims()->all();
        $subjectExpiresAt = $this->claimTimestamp($claims['exp'] ?? null);

        if ($subjectExpiresAt <= time()) {
            $this->deny($requestingClient, 'subject_token_expired', 'The subject token has expired.');
        }

        $dbExpiresAt = $dbToken->getAttribute('expires_at');
        if ($dbExpiresAt instanceof DateTimeInterface && $dbExpiresAt->getTimestamp() <= time()) {
            $this->deny($requestingClient, 'subject_token_expired', 'The subject token has expired.');
        }

        $result = $this->policy->authorize(new ExchangeRequest(
            client: $requestingClient,
            subjectClaims: $claims,
            requestedAudience: $audience,
            requestedScopes: $scopes,
            subjectExpiresAt: $subjectExpiresAt,
            parameters: $parameters,
        ));

        $scopeIds = $this->scopes->finalize($result->scopes, self::GRANT_URN, $requestingClient, $result->userId);

        $user = $this->resolveUser($result->userId);

        if ($user === null) {
            $this->deny($requestingClient, 'subject_user_missing', 'The subject token user no longer exists.');
        }

        $api = $this->pipeline->run('token_exchange', new TokenExchangeEvent(
            user: $user,
            client: $requestingClient,
            scopes: $scopeIds,
            audience: $result->audience[0] ?? $requestingClient->client_id,
            subjectClaims: $claims,
        ), $result->context);

        if ($api->isDenied()) {
            $this->auditor->log(AuditEventType::TokenIssuanceFailed, userId: $result->userId, clientId: $requestingClient->client_id, context: array_filter([
                'grant_type' => self::GRANT_URN,
                'reason' => 'pipeline_denied',
                'deny_reason' => $api->denyReason(),
            ]));

            throw ExchangeDeniedException::accessDenied((string) $api->denyReason());
        }

        $ttl = $this->cappedTtl($accessTokenTTL ?? $this->realms->current()->tokens()->accessToken(), $result->expiresAt);

        $act = ['client_id' => $requestingClient->client_id];

        if (isset($claims['act']) && is_array($claims['act'])) {
            $act['act'] = $claims['act'];
        }

        $token = $this->minter->mint($result->userId, $requestingClient->client_id, $scopeIds, $ttl, $result->audience, $api->accessTokenClaims(), $act);

        $this->auditor->log(AuditEventType::TokenIssued, userId: $result->userId, clientId: $requestingClient->client_id, context: [
            'grant_type' => self::GRANT_URN,
            'jti' => $token->jti,
            'audience' => $result->audience,
            'scopes' => $scopeIds,
        ]);

        return $token;
    }

    private function deny(Client $requestingClient, string $reason, string $message): never
    {
        $this->auditor->log(AuditEventType::TokenIssuanceFailed, clientId: $requestingClient->client_id, context: [
            'grant_type' => self::GRANT_URN,
            'reason' => $reason,
        ]);

        throw ExchangeDeniedException::invalidGrant($message);
    }

    private function cappedTtl(DateInterval $default, int $subjectExpiresAt): DateInterval
    {
        $defaultExpiry = (new DateTimeImmutable)->add($default)->getTimestamp();
        $seconds = max(1, min($defaultExpiry, $subjectExpiresAt) - time());

        return new DateInterval('PT'.$seconds.'S');
    }

    private function claimTimestamp(mixed $exp): int
    {
        if ($exp instanceof DateTimeImmutable) {
            return $exp->getTimestamp();
        }

        return is_numeric($exp) ? (int) $exp : 0;
    }
}
