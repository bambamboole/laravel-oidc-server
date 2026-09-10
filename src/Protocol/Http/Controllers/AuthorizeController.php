<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Authentication\LoginDestination;
use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Protocol\Authorize\AuthorizationCodeIssuer;
use Bambamboole\LaravelOidc\Server\Protocol\Authorize\AuthorizeRequest;
use Bambamboole\LaravelOidc\Server\Protocol\Authorize\AuthorizeRequestSession;
use Bambamboole\LaravelOidc\Server\Protocol\Authorize\AuthorizeRequestValidator;
use Bambamboole\LaravelOidc\Server\Scopes\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Bambamboole\LaravelOidc\Server\Shared\Authentication\AuthSessionState;
use Bambamboole\LaravelOidc\Server\Shared\Consents\AuthorizationViewResponse;
use Bambamboole\LaravelOidc\Server\Shared\Consents\ConsentStore;
use Bambamboole\LaravelOidc\Server\Shared\Http\RespondsToInertiaExternalRedirects;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\OAuthServerException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Symfony\Component\HttpFoundation\Response;

/**
 * The authorization endpoint (OAuth 2.1 §4.1.1, OpenID Connect Core §3.1.2),
 * reached by GET or POST (§3.1.2.1). The request is validated before anything
 * touches the session, then `max_age` and `prompt` decide whether the
 * current login may be reused.
 *
 * This provider holds one account per browser session, so `select_account`
 * has no account to switch to and is treated exactly like `login`: the
 * session is torn down and the user authenticates again.
 */
class AuthorizeController
{
    use RespondsToInertiaExternalRedirects;

    public function __construct(
        protected AuthorizeRequestValidator $validator,
        protected AuthorizeRequestSession $pending,
        protected AuthorizationCodeIssuer $codes,
        protected StatefulGuard $guard,
        protected ClientRepository $clients,
        protected ScopeRepository $scopeRepository,
        private readonly LoginDestination $loginDestination,
        private readonly FirstPartyClientConfig $firstPartyClient,
        private readonly AuthSessionState $sessionState,
        private readonly ConsentStore $consents,
    ) {}

    public function __invoke(Request $request, AuthorizationViewResponse $viewResponse): Response|AuthorizationViewResponse
    {
        $authRequest = $this->validator->validate($request);

        $this->rememberRequestedAcrValues($authRequest);

        $prompt = $this->prompt($authRequest);
        $user = $this->guard->user();

        if ($user === null) {
            $prompt->contains('none')
                ? throw OAuthServerException::loginRequired($authRequest->redirectUri, $authRequest->state)
                : $this->promptForLogin($request);
        }

        // OIDC Core §3.1.2.1: the hint names the user the client expects; a
        // session belonging to somebody else must not be reused.
        if ($authRequest->idTokenHintSubject !== null && $authRequest->idTokenHintSubject !== (string) $user->getAuthIdentifier()) {
            throw OAuthServerException::loginRequired($authRequest->redirectUri, $authRequest->state);
        }

        if ($this->exceedsMaxAge($authRequest) || $prompt->contains('login') || $prompt->contains('select_account')) {
            $this->reauthenticate($request, $authRequest, $prompt);
        }

        $request->session()->forget('oidc.prompted_for_login');

        $authRequest->userId = (string) $user->getAuthIdentifier();

        $scopes = $this->parseScopes($authRequest);
        $client = $this->clients->find($authRequest->clientId);

        if ($prompt->doesntContain('consent')
            && $client instanceof Client
            && ($client->skipsConsent() || $this->hasGrantedScopes($user, $client, $scopes))) {
            return $this->respondToInertia($request, $this->codes->approve($authRequest));
        }

        if ($prompt->contains('none')) {
            throw OAuthServerException::consentRequired($authRequest->redirectUri, $authRequest->state);
        }

        $authToken = $this->pending->stash($request, $authRequest);

        return $viewResponse->withParameters([
            'client' => $client,
            'user' => $user,
            'scopes' => $scopes,
            'request' => $request,
            'authToken' => $authToken,
        ]);
    }

    /**
     * A trusted first-party client never shows consent, so its `consent`
     * prompt is dropped.
     *
     * @return Collection<int, string>
     */
    protected function prompt(AuthorizeRequest $authRequest): Collection
    {
        $prompt = collect($authRequest->prompt);

        return $this->firstPartyClient->isTrusted($authRequest->clientId)
            ? $prompt->reject(fn (string $value): bool => $value === 'consent')->values()
            : $prompt;
    }

    /**
     * A hidden scope is granted but never shown, so it neither appears on the
     * consent screen nor keeps a stored consent from covering the request.
     *
     * @return list<Scope>
     */
    protected function parseScopes(AuthorizeRequest $authRequest): array
    {
        return collect($authRequest->scopes)
            ->map(fn (string $id): ?Scope => $this->scopeRepository->find($id))
            ->filter(fn (?Scope $scope): bool => $scope instanceof Scope && ! $scope->hidden)
            ->values()
            ->all();
    }

    /**
     * A trusted first-party client is consented to implicitly; anyone else
     * needs a stored consent covering every requested scope.
     *
     * @param  list<Scope>  $scopes
     */
    protected function hasGrantedScopes(Authenticatable $user, Client $client, array $scopes): bool
    {
        if ($this->firstPartyClient->isTrusted($client->client_id)) {
            return true;
        }

        return $this->consents->covers(
            (string) $user->getAuthIdentifier(),
            (string) $client->getKey(),
            array_map(fn (Scope $scope): string => $scope->id, $scopes),
        );
    }

    protected function promptForLogin(Request $request): never
    {
        $request->session()->put('oidc.prompted_for_login', true);

        throw new AuthenticationException(
            guards: [(string) config('oidc.auth.guard', 'identity')],
            redirectTo: $this->loginDestination->url(),
        );
    }

    /**
     * OIDC Core §3.1.2.1: a login older than `max_age` must be renewed; a
     * missing auth_time counts as stale.
     */
    protected function exceedsMaxAge(AuthorizeRequest $authRequest): bool
    {
        if ($authRequest->maxAge === null) {
            return false;
        }

        return time() - ($this->sessionState->authTime() ?? 0) >= $authRequest->maxAge;
    }

    /**
     * OIDC Core §3.1.2.6: with `prompt=none` a stale login is reported as
     * `login_required` and the session is left intact. Otherwise the session
     * is torn down and the user sent to login; `oidc.prompted_for_login` marks the
     * return trip so the forced login does not loop.
     *
     * @param  Collection<int, string>  $prompt
     */
    protected function reauthenticate(Request $request, AuthorizeRequest $authRequest, Collection $prompt): void
    {
        if ($prompt->contains('none')) {
            throw OAuthServerException::loginRequired($authRequest->redirectUri, $authRequest->state);
        }

        if ($request->session()->get('oidc.prompted_for_login', false)) {
            return;
        }

        $this->guard->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        $this->promptForLogin($request);
    }

    /**
     * The pending authorize request is stashed only at consent time — after
     * login — so acr_values must be persisted here for the post-login pipeline
     * to see it. Synced on every authorize request so a flow without acr_values
     * clears an earlier flow's leftovers.
     */
    private function rememberRequestedAcrValues(AuthorizeRequest $authRequest): void
    {
        $this->sessionState->putRequestedAcrValues($authRequest->acrValues);
    }
}
