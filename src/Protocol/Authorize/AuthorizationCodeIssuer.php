<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Authorize;

use Bambamboole\LaravelOidc\Server\Authentication\Context\AuthenticationContextStore;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Sessions\OidcSessionRepository;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AcrResolver;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AuthorizationCode;
use DateInterval;
use DateTimeImmutable;
use Illuminate\Http\RedirectResponse;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Turns an approved authorization request into the code redirect (OAuth 2.1
 * §4.1.2, with the RFC 9207 §2 `iss` parameter), snapshotting the login into
 * an authentication context the token endpoint links every descendant token to.
 */
final readonly class AuthorizationCodeIssuer
{
    private const string TTL = 'PT10M';

    public function __construct(
        private ClientRepository $clients,
        private AuthenticationContextStore $contexts,
        private OidcSessionRepository $sessions,
        private AuthSessionState $sessionState,
        private AcrResolver $acr,
        private RealmResolver $realms,
        private IssuerResolver $issuer,
    ) {}

    public function approve(AuthorizeRequest $request): RedirectResponse
    {
        $userId = $request->userId ?? throw new LogicException('An authorization request cannot be approved without a user.');

        $client = $this->clients->findActive($request->clientId)
            ?? throw OAuthServerException::invalidRequest('The client is unknown.');

        $authTime = $this->sessionState->authTime() ?? time();
        $sid = $this->sessionState->sid();

        $code = bin2hex(random_bytes(40));

        AuthorizationCode::query()->forceCreate([
            'realm_id' => AuthorizationCode::currentRealm(),
            'code' => $code,
            'user_id' => $userId,
            'client_id' => $client->getKey(),
            'scopes' => $request->scopes,
            'audience' => $request->resources,
            'redirect_uri' => $request->redirectUriRequested ? $request->redirectUri : null,
            'code_challenge' => $request->codeChallenge,
            'code_challenge_method' => $request->codeChallengeMethod,
            'nonce' => $request->nonce,
            'auth_time' => $authTime,
            'context_id' => $this->createContext($userId, $sid, $authTime),
            'expires_at' => (new DateTimeImmutable)->add(new DateInterval(self::TTL)),
        ]);

        if ($sid !== null) {
            $this->sessions->recordParticipant($sid, (string) $client->getKey());
        }

        return new RedirectResponse($this->appendQuery($request->redirectUri, array_filter([
            'code' => $code,
            'state' => $request->state,
            'iss' => $this->issuer->url(),
        ], fn (?string $value): bool => $value !== null)));
    }

    /** @param  array<string, string>  $parameters */
    private function appendQuery(string $uri, array $parameters): string
    {
        return $uri.(str_contains($uri, '?') ? '&' : '?').http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    public function deny(AuthorizeRequest $request): Response
    {
        return OAuthServerException::accessDenied('The user denied the request.', $request->redirectUri, $request->state)->getResponse();
    }

    private function createContext(string $userId, ?string $sid, int $authTime): string
    {
        $amr = $this->sessionState->amr();
        $session = $sid !== null ? $this->sessions->find($sid) : null;

        $expiresAt = $session?->expires_at?->toDateTimeImmutable()
            ?? (new DateTimeImmutable)->add($this->realms->current()->sessions()->absolute());

        return $this->contexts->create([
            'user_id' => $userId,
            'sid' => $sid,
            'amr' => $amr,
            'acr' => $this->acr->fromAmr($amr),
            'auth_time' => $authTime,
            'id_token_claims' => $this->sessionState->idTokenClaims(),
            'access_token_claims' => $this->sessionState->accessTokenClaims(),
            'expires_at' => $expiresAt,
        ]);
    }
}
