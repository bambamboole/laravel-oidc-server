<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http\Controllers;

use Bambamboole\LaravelOidc\Auth\LoginDestination;
use Bambamboole\LaravelOidc\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Scopes\Scope;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Contracts\AuthorizationViewResponse;
use Laravel\Passport\Http\Controllers\AuthorizationController as PassportAuthorizationController;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Response;

class AuthorizationController extends PassportAuthorizationController
{
    public function __construct(
        AuthorizationServer $server,
        StatefulGuard $guard,
        ClientRepository $clients,
        protected ScopeRepository $scopeRepository,
        private readonly LoginDestination $loginDestination,
        private readonly FirstPartyClientConfig $firstPartyClient,
    ) {
        parent::__construct($server, $guard, $clients);
    }

    public function authorize(
        ServerRequestInterface $psrRequest,
        Request $request,
        ResponseInterface $psrResponse,
        AuthorizationViewResponse $viewResponse
    ): Response|AuthorizationViewResponse {
        $this->removeConsentPromptForTrustedClient($request);
        $this->enforceMaxAge($request);

        return parent::authorize($psrRequest, $request, $psrResponse, $viewResponse);
    }

    protected function hasGrantedScopes(Authenticatable $user, Client $client, array $scopes): bool
    {
        return $this->isTrustedClient($client->getKey()) || parent::hasGrantedScopes($user, $client, $scopes);
    }

    protected function promptForLogin(Request $request): never
    {
        $request->session()->put('promptedForLogin', true);

        throw new AuthenticationException(
            guards: [(string) config('oidc.auth.guard', 'identity')],
            redirectTo: $this->loginDestination->url(),
        );
    }

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

    protected function enforceMaxAge(Request $request): void
    {
        $maxAge = $request->query('max_age');

        if ($maxAge === null || ! is_numeric($maxAge) || $this->guard->guest()) {
            return;
        }

        // A stale-but-valid session must never be torn down before the request
        // itself is trustworthy. Without a resolvable, non-revoked client the
        // logout would be a cross-site logout vector (e.g. an <img> tag hitting
        // /oauth/authorize?max_age=1). Defer to parent::authorize to reject.
        $clientId = $request->query('client_id');

        if (! is_string($clientId) || $this->clients->findActive($clientId) === null) {
            return;
        }

        // Mirrors Passport's prompt=login loop guard: after the forced login
        // redirect returns here, promptedForLogin is set, so we don't force again.
        if ($request->session()->get('promptedForLogin', false)) {
            return;
        }

        $authTime = (int) $request->session()->get('oidc.auth_time', 0);

        if (time() - $authTime >= (int) $maxAge) {
            $this->guard->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            $this->promptForLogin($request);
        }
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
