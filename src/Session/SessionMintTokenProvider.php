<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Session;

use Bambamboole\LaravelOidc\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Contracts\SessionTokenProvider;
use Bambamboole\LaravelOidc\Scopes\Scope;
use Bambamboole\LaravelOidc\Token\AccessTokenMinter;
use DateInterval;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Auth;
use Laravel\Passport\Passport;
use RuntimeException;

/**
 * This is a singleton, so the session/auth stores and the first-party client
 * config must never be injected via the constructor — that would capture
 * request-scoped (or test-mutated) state on first resolution and leak it
 * across requests. They are resolved lazily, per call, inside each method.
 */
class SessionMintTokenProvider implements SessionTokenProvider
{
    public function __construct(
        private readonly AccessTokenMinter $minter,
        private readonly ScopeRepository $scopes,
    ) {}

    public function currentToken(): ?string
    {
        $stored = $this->session()->get($this->key());
        $currentUserId = Auth::guard()->id();

        if (is_array($stored)
            && is_string($stored['jwt'] ?? null)
            && ($stored['user_id'] ?? null) === ($currentUserId === null ? null : (string) $currentUserId)
            && ((int) ($stored['expires_at'] ?? 0)) - time() > $this->skew()) {
            return $stored['jwt'];
        }

        $user = Auth::guard()->user();

        if ($user === null) {
            return null;
        }

        $this->establish($user);

        return $this->session()->get($this->key())['jwt'] ?? null;
    }

    public function establish(Authenticatable $user): void
    {
        $client = Passport::client()->newQuery()->find(app(FirstPartyClientConfig::class)->clientId());

        if ($client === null) {
            throw new RuntimeException('The oidc.first_party.client_id is not configured or does not exist.');
        }

        $prior = $this->session()->get($this->key());

        if (is_array($prior) && is_string($prior['jti'] ?? null)) {
            Passport::token()->newQuery()->whereKey($prior['jti'])->update(['revoked' => true]);
        }

        $ttl = (int) config('oidc.session_token.ttl', 3600);
        $token = $this->minter->mint(
            (string) $user->getAuthIdentifier(),
            $client,
            $this->defaultScopes(),
            new DateInterval('PT'.$ttl.'S'),
        );

        $this->session()->put($this->key(), [
            'jwt' => $token->toString(),
            'jti' => $token->getIdentifier(),
            'user_id' => (string) $user->getAuthIdentifier(),
            'expires_at' => $token->getExpiryDateTime()->getTimestamp(),
        ]);
    }

    public function forget(): void
    {
        $stored = $this->session()->get($this->key());

        if (is_array($stored) && is_string($stored['jti'] ?? null)) {
            Passport::token()->newQuery()->whereKey($stored['jti'])->update(['revoked' => true]);
        }

        $this->session()->forget($this->key());
    }

    private function session(): Session
    {
        return app('session.store');
    }

    /** @return string[] */
    private function defaultScopes(): array
    {
        $configured = config('oidc.session_token.scopes');

        if (is_array($configured)) {
            return $configured;
        }

        return $this->scopes->all()->reject(fn (Scope $scope) => $scope->hidden)->map(fn (Scope $scope) => $scope->id)->values()->all();
    }

    private function key(): string
    {
        return (string) config('oidc.session_token.session_key', 'oidc.session_token');
    }

    private function skew(): int
    {
        return (int) config('oidc.session_token.refresh_skew', 60);
    }
}
