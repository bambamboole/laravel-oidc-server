<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Grant;

use Bambamboole\LaravelOidc\Auth\AuthenticationContextStore;
use Bambamboole\LaravelOidc\Auth\AuthenticationMethods;
use Bambamboole\LaravelOidc\Auth\Models\AuthenticationContext;
use Bambamboole\LaravelOidc\Auth\SessionRegistry;
use Bambamboole\LaravelOidc\Grant\Concerns\HasAuthenticationContextIssuance;
use Bambamboole\LaravelOidc\Responses\IdTokenResponse;
use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

class OidcAuthCodeGrant extends AuthCodeGrant
{
    use HasAuthenticationContextIssuance;

    /**
     * league v9 declares AuthCodeGrant::$authCodeTTL private, so the forked
     * completeAuthorizationRequest() below cannot read the parent's copy; mirror it here.
     */
    protected DateInterval $authCodeTTL;

    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        DateInterval $authCodeTTL,
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authCodeTTL);
        $this->authCodeTTL = $authCodeTTL;
    }

    protected function createAuthorizationRequest(): AuthorizationRequestInterface
    {
        return new OidcAuthorizationRequest;
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $authorizationRequest = parent::validateAuthorizationRequest($request);

        if ($authorizationRequest instanceof OidcAuthorizationRequest) {
            $authorizationRequest->setNonce($this->getQueryStringParameter('nonce', $request));
        }

        // OAuth 2.1 §4.1.1 / §7.6: PKCE is REQUIRED for every client, not only public ones
        // (league's default only mandates it for public clients).
        if ($authorizationRequest->getCodeChallenge() === null) {
            throw OAuthServerException::invalidRequest('code_challenge', 'Code challenge required.');
        }

        return $authorizationRequest;
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        // Defense-in-depth: AuthorizationServer (and this grant) is a container singleton,
        // so under Octane it persists across requests. League's parent validates the
        // client, auth code, scopes, and PKCE *before* ever calling issueAccessToken() —
        // the only place pendingContext is normally cleared. If any of that validation
        // throws, a pendingContext set below would otherwise survive into the next
        // request. Clear it unconditionally at entry so a stale value never leaks.
        $this->pendingContext = null;

        if ($responseType instanceof IdTokenResponse) {
            $encryptedAuthCode = $this->getRequestParameter('code', $request);

            if ($encryptedAuthCode !== null) {
                try {
                    $payload = json_decode($this->decrypt($encryptedAuthCode));
                    $responseType->setNonce($payload->nonce ?? null);
                    $responseType->setAuthTime(isset($payload->auth_time) ? (int) $payload->auth_time : null);

                    $context = $this->context(app(AuthenticationContextStore::class), $payload->context_id ?? null);
                    if ($context !== null) {
                        $this->pendingContext = $context;
                        $responseType->setAmr($context->amr);
                        $responseType->setIdTokenClaims($context->id_token_claims);
                        $responseType->setSid($context->sid);
                    }
                } catch (\Throwable) {
                    // Parent will reject the malformed code with a proper OAuth error.
                }
            }
        }

        return parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
    }

    /**
     * Fork of League\OAuth2\Server\Grant\AuthCodeGrant::completeAuthorizationRequest() (league v9),
     * kept byte-identical except for the added `nonce`, `auth_time`, and `context_id` payload keys so
     * future league diffs remain easy to port.
     */
    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): ResponseTypeInterface
    {
        if ($authorizationRequest->getUser() instanceof UserEntityInterface === false) {
            throw new LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        $finalRedirectUri = $authorizationRequest->getRedirectUri()
                          ?? $this->getClientRedirectUri($authorizationRequest->getClient());

        if ($authorizationRequest->isAuthorizationApproved() === true) {
            $authCode = $this->issueAuthCode(
                $this->authCodeTTL,
                $authorizationRequest->getClient(),
                $authorizationRequest->getUser()->getIdentifier(),
                $authorizationRequest->getRedirectUri(),
                $authorizationRequest->getScopes()
            );

            $payload = [
                'client_id' => $authCode->getClient()->getIdentifier(),
                'redirect_uri' => $authCode->getRedirectUri(),
                'auth_code_id' => $authCode->getIdentifier(),
                'scopes' => $authCode->getScopes(),
                'user_id' => $authCode->getUserIdentifier(),
                'expire_time' => (new DateTimeImmutable)->add($this->authCodeTTL)->getTimestamp(),
                'code_challenge' => $authorizationRequest->getCodeChallenge(),
                'code_challenge_method' => $authorizationRequest->getCodeChallengeMethod(),
                'nonce' => $authorizationRequest instanceof OidcAuthorizationRequest
                    ? $authorizationRequest->getNonce()
                    : null,
                'auth_time' => $this->currentAuthTime(),
                'context_id' => $this->finalizeContext($authorizationRequest->getUser()->getIdentifier()),
            ];

            $sid = $this->currentSid();
            if ($sid !== null) {
                app(SessionRegistry::class)->recordParticipant($sid, $authorizationRequest->getClient()->getIdentifier());
            }

            $jsonPayload = json_encode($payload);

            if ($jsonPayload === false) {
                throw new LogicException('An error was encountered when JSON encoding the authorization request response');
            }

            $response = new RedirectResponse;
            $response->setRedirectUri(
                $this->makeRedirectUri(
                    $finalRedirectUri,
                    [
                        'code' => $this->encrypt($jsonPayload),
                        'state' => $authorizationRequest->getState(),
                    ]
                )
            );

            return $response;
        }

        throw OAuthServerException::accessDenied(
            'The user denied the request',
            $this->makeRedirectUri(
                $finalRedirectUri,
                ['state' => $authorizationRequest->getState()]
            )
        );
    }

    private function sessionValue(string $key, mixed $default): mixed
    {
        if (app()->bound('session.store') && app('session.store')->isStarted()) {
            return app('session.store')->get($key, $default);
        }

        return $default;
    }

    private function currentAuthTime(): int
    {
        return (int) $this->sessionValue('oidc.auth_time', time());
    }

    private function finalizeContext(string $userId): string
    {
        $amr = $this->currentAmr();
        $sid = $this->currentSid();
        $session = is_string($sid) ? app(SessionRegistry::class)->find($sid) : null;

        $expiresAt = $session?->expires_at?->toDateTimeImmutable()
            ?? (new DateTimeImmutable)->add(
                new DateInterval('PT'.(int) config('oidc.session.absolute_lifetime').'S'),
            );

        return app(AuthenticationContextStore::class)->create([
            'user_id' => $userId,
            'sid' => $sid,
            'amr' => $amr,
            'acr' => AuthenticationMethods::deriveAcr($amr),
            'auth_time' => $this->currentAuthTime(),
            'id_token_claims' => $this->currentIdTokenClaims(),
            'access_token_claims' => $this->currentAccessTokenClaims(),
            'expires_at' => $expiresAt,
        ]);
    }

    private function currentSid(): ?string
    {
        $sid = $this->sessionValue('oidc.sid', null);

        return is_string($sid) && $sid !== '' ? $sid : null;
    }

    /** @return array<string, mixed> */
    private function currentAccessTokenClaims(): array
    {
        $claims = $this->sessionValue('oidc.access_token_claims', []);

        return is_array($claims) ? $claims : [];
    }

    private function context(AuthenticationContextStore $store, mixed $id): ?AuthenticationContext
    {
        return is_string($id) && $id !== '' ? $store->find($id) : null;
    }

    /** @return list<string> */
    private function currentAmr(): array
    {
        $amr = $this->sessionValue(AuthenticationMethods::SESSION_KEY, []);

        return is_array($amr) ? array_values(array_filter($amr, is_string(...))) : [];
    }

    /** @return array<string, mixed> */
    private function currentIdTokenClaims(): array
    {
        $claims = $this->sessionValue('oidc.id_token_claims', []);

        return is_array($claims) ? $claims : [];
    }
}
