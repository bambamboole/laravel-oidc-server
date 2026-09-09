<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Controllers;

use Bambamboole\LaravelOidc\Server\Authentication\LoginDestination;
use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Protocol\Concerns\HandlesOAuthErrors;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\UserEntity;
use Bambamboole\LaravelOidc\Server\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Shared\Consents\AuthorizationViewResponse;
use Bambamboole\LaravelOidc\Server\Shared\Http\ConvertsPsrResponses;
use Bambamboole\LaravelOidc\Server\Shared\Http\RespondsToInertiaExternalRedirects;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Str;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Response;

class AuthorizationController
{
    use ConvertsPsrResponses, HandlesOAuthErrors, RespondsToInertiaExternalRedirects;

    public function __construct(
        protected AuthorizationServer $server,
        protected StatefulGuard $guard,
        protected ClientRepository $clients,
        protected ScopeRepository $scopeRepository,
        private readonly LoginDestination $loginDestination,
        private readonly FirstPartyClientConfig $firstPartyClient,
        private readonly AuthSessionState $sessionState,
    ) {}

    public function authorize(
        ServerRequestInterface $psrRequest,
        Request $request,
        ResponseInterface $psrResponse,
        AuthorizationViewResponse $viewResponse,
    ): Response|AuthorizationViewResponse {
        $this->removeConsentPromptForTrustedClient($request);
        $this->rememberRequestedAcrValues($request);
        $this->enforceMaxAge($request);

        $authRequest = $this->withErrorHandling(
            fn (): AuthorizationRequestInterface => $this->server->validateAuthorizationRequest($psrRequest),
        );

        $prompt = $this->prompt($request);

        if ($this->guard->guest()) {
            $prompt->contains('none')
                ? throw OAuthServerException::loginRequired($authRequest)
                : $this->promptForLogin($request);
        }

        if ($prompt->contains('login') && ! $request->session()->get('promptedForLogin', false)) {
            $this->guard->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            $this->promptForLogin($request);
        }

        $request->session()->forget('promptedForLogin');

        $user = $this->guard->user();
        $authRequest->setUser(new UserEntity((string) $user?->getAuthIdentifier()));

        $scopes = $this->parseScopes($authRequest);
        $client = $this->clients->find($authRequest->getClient()->getIdentifier());

        if ($prompt->doesntContain('consent')
            && $client !== null
            && $user !== null
            && ($client->skipsConsent() || $this->hasGrantedScopes($user, $client, $scopes))) {
            return $this->respondToInertia($request, $this->approveRequest($authRequest, $psrResponse));
        }

        if ($prompt->contains('none')) {
            throw OAuthServerException::consentRequired($authRequest);
        }

        $request->session()->put('authToken', $authToken = Str::random());
        $request->session()->put('authRequest', serialize($authRequest));

        return $viewResponse->withParameters([
            'client' => $client,
            'user' => $user,
            'scopes' => $scopes,
            'request' => $request,
            'authToken' => $authToken,
        ]);
    }

    /**
     * OIDC Core §3.1.2.1: `none` overrides every other value, because the whole
     * point is that nothing interactive may happen.
     *
     * @return Collection<int, string>
     */
    protected function prompt(Request $request): Collection
    {
        $prompt = $request->string('prompt')->explode(' ')->map(fn (string $value): string => trim($value))->filter()->values();

        return $prompt->contains('none') ? collect(['none']) : $prompt;
    }

    /** @return list<Scope> */
    protected function parseScopes(AuthorizationRequestInterface $authRequest): array
    {
        return collect($authRequest->getScopes())
            ->map(fn (ScopeEntityInterface $scope): string => $scope->getIdentifier())
            ->unique()
            ->map(fn (string $id): ?Scope => $this->scopeRepository->find($id))
            ->filter()
            ->values()
            ->all();
    }

    /** @param  list<Scope>  $scopes */
    protected function hasGrantedScopes(Authenticatable $user, Client $client, array $scopes): bool
    {
        if ($this->isTrustedClient($client->client_id)) {
            return true;
        }

        $activeTokens = $client->tokens()->where([
            ['user_id', '=', $user->getAuthIdentifier()],
            ['revoked', '=', false],
            ['expires_at', '>', Date::now()],
        ]);

        if ($scopes === []) {
            return $activeTokens->exists();
        }

        return collect($scopes)->pluck('id')->diff(
            $activeTokens->pluck('scopes')->flatten()
        )->isEmpty();
    }

    protected function approveRequest(AuthorizationRequestInterface $authRequest, ResponseInterface $psrResponse): Response
    {
        $authRequest->setAuthorizationApproved(true);

        return $this->withErrorHandling(fn (): Response => $this->convertResponse(
            $this->server->completeAuthorizationRequest($authRequest, $psrResponse)
        ), $authRequest->getGrantTypeId() === 'implicit');
    }

    protected function promptForLogin(Request $request): never
    {
        $request->session()->put('promptedForLogin', true);

        throw new AuthenticationException(
            guards: [(string) config('oidc.auth.guard', 'identity')],
            redirectTo: $this->loginDestination->url(),
        );
    }

    protected function enforceMaxAge(Request $request): void
    {
        $maxAge = $request->query('max_age');

        if ($maxAge === null || ! is_numeric($maxAge) || $this->guard->guest()) {
            return;
        }

        // A stale-but-valid session must never be torn down before the request
        // itself is trustworthy. Without a resolvable, non-revoked client the
        // logout would be a cross-site logout vector (e.g. an <img> tag hitting
        // /oauth/authorize?max_age=1). Defer to request validation to reject.
        $clientId = $request->query('client_id');

        if (! is_string($clientId) || $this->clients->findActive($clientId) === null) {
            return;
        }

        // Mirrors the prompt=login loop guard: after the forced login redirect
        // returns here, promptedForLogin is set, so we don't force again.
        if ($request->session()->get('promptedForLogin', false)) {
            return;
        }

        $authTime = $this->sessionState->authTime() ?? 0;

        if (time() - $authTime >= (int) $maxAge) {
            $this->guard->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            $this->promptForLogin($request);
        }
    }

    /**
     * The pending authorize request is stashed only at consent time — after
     * login — so acr_values must be persisted here for the post-login pipeline
     * to see it. Synced on every authorize request so a flow without acr_values
     * clears an earlier flow's leftovers.
     */
    private function rememberRequestedAcrValues(Request $request): void
    {
        $acrValues = $request->query('acr_values');

        $this->sessionState->putRequestedAcrValues(is_string($acrValues)
            ? array_values(array_filter(explode(' ', $acrValues), static fn (string $value): bool => $value !== ''))
            : []);
    }

    private function removeConsentPromptForTrustedClient(Request $request): void
    {
        if (! $this->isTrustedClient($request->query('client_id'))) {
            return;
        }

        $prompt = $request->string('prompt')
            ->explode(' ')
            ->map(fn (string $value): string => trim($value))
            ->reject(fn (string $value): bool => $value === 'consent')
            ->filter()
            ->implode(' ');

        $request->query->set('prompt', $prompt);
    }

    private function isTrustedClient(mixed $clientId): bool
    {
        return (is_string($clientId) || is_int($clientId))
            && $this->firstPartyClient->isTrusted($clientId);
    }
}
