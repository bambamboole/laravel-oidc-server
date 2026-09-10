<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions;

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Scopes\Scope;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Bambamboole\LaravelOidc\Server\Shared\Sessions\SessionTokenProvider;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenRevoker;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Auth;

/**
 * This is a singleton, so the session/auth stores and the first-party client
 * config must never be injected via the constructor — that would capture
 * request-scoped (or test-mutated) state on first resolution and leak it
 * across requests. They are resolved lazily, per call, inside each method.
 */
class SessionTokenIssuer implements SessionTokenProvider
{
    public function __construct(
        private readonly ClientRepository $clients,
        private readonly AccessTokenMinter $minter,
        private readonly AccessTokenRevoker $revoker,
        private readonly ScopeRepository $scopes,
        private readonly RealmResolver $realms,
    ) {}

    public function currentToken(): ?string
    {
        $stored = $this->session()->get($this->key());
        $currentUserId = $this->guard()->id();

        if (is_array($stored)
            && is_string($stored['jwt'] ?? null)
            && ($stored['user_id'] ?? null) === ($currentUserId === null ? null : (string) $currentUserId)
            && ((int) ($stored['expires_at'] ?? 0)) - time() > $this->skew()) {
            return $stored['jwt'];
        }

        $user = $this->guard()->user();

        if ($user === null) {
            return null;
        }

        $this->establish($user);

        return $this->session()->get($this->key())['jwt'] ?? null;
    }

    public function establish(Authenticatable $user): void
    {
        $client = $this->clients->firstParty(app(FirstPartyClientConfig::class));

        $prior = $this->session()->get($this->key());

        if (is_array($prior) && is_string($prior['jti'] ?? null)) {
            $this->revoker->revoke($prior['jti']);
        }

        $token = $this->minter->mint(
            (string) $user->getAuthIdentifier(),
            $client->client_id,
            $this->defaultScopes(),
            $this->realms->current()->sessions()->token(),
        );

        $this->session()->put($this->key(), [
            'jwt' => $token->jwt,
            'jti' => $token->jti,
            'user_id' => (string) $user->getAuthIdentifier(),
            'expires_at' => $token->expiresAt->getTimestamp(),
        ]);
    }

    public function forget(): void
    {
        $stored = $this->session()->get($this->key());

        if (is_array($stored) && is_string($stored['jti'] ?? null)) {
            $this->revoker->revoke($stored['jti']);
        }

        $this->session()->forget($this->key());
    }

    private function session(): Session
    {
        return app('session.store');
    }

    private function guard(): Guard
    {
        return Auth::guard(SessionTokenGuard::name());
    }

    /** @return string[] */
    private function defaultScopes(): array
    {
        $configured = $this->realms->current()->sessions()->tokenScopes;

        if ($configured !== null) {
            return $configured;
        }

        return $this->scopes->all()->reject(fn (Scope $scope): bool => $scope->hidden)->map(fn (Scope $scope): string => $scope->id)->values()->all();
    }

    private function key(): string
    {
        return (string) config('oidc.session.token.session_key', 'oidc.session_token');
    }

    private function skew(): int
    {
        return $this->realms->current()->sessions()->tokenRefreshSkew;
    }
}
