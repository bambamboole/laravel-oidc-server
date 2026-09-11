<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Guard;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\RealmAudiences;
use Bambamboole\LaravelOidc\Server\Tokens\Concerns\ResolvesTokenUser;
use Bambamboole\LaravelOidc\Server\Tokens\Contracts\AccessTokenBearer;
use Bambamboole\LaravelOidc\Server\Tokens\Http\Middleware\CheckAudience;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\TokenInspector;
use DateTimeInterface;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;
use Lcobucci\JWT\Token\Plain;

/**
 * Purpose-built `auth:oidc` guard: a self-contained RFC 9068 resource-server validator (signature,
 * `at+jwt` typ, expiry, revocation via {@see TokenInspector}) that accepts a bearer token only when
 * its `aud` names one of the realm's audiences ({@see RealmAudiences}; RFC 9068 §4). A token
 * addressed elsewhere — another resource, or a client id — is rejected regardless of which client
 * it was issued to. The verified audience is stashed on the request for {@see CheckAudience} to
 * narrow further without re-parsing the token.
 *
 * The principal is the token's user, or a {@see ClientPrincipal} when the token carries no subject.
 *
 * The user provider comes from this guard's own `auth.guards.{name}.provider` config entry (handed
 * in by `Auth::extend()`), not from {@see ResolvesTokenUser} — that trait resolves via
 * the OIDC auth guard's provider instead, which is this package's *identity* guard, not necessarily
 * the one configured for this guard.
 */
class AccessTokenGuard implements Guard
{
    use GuardHelpers, Macroable;

    public function __construct(
        private readonly TokenInspector $inspector,
        UserProvider $provider,
        private Request $request,
    ) {
        $this->setProvider($provider);
    }

    public function user(): ?Authenticatable
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $jwt = $this->request->bearerToken();

        if ($jwt === null) {
            return null;
        }

        $token = $this->verifyBearerToken($jwt);

        if (! $token instanceof AccessToken) {
            return null;
        }

        $principal = $this->principalFor($token);

        if (! $principal instanceof Authenticatable) {
            return null;
        }

        return $this->user = $principal instanceof AccessTokenBearer
            ? $principal->withAccessToken(new CurrentAccessToken($token))
            : $principal;
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        $request = $credentials['request'] ?? null;

        if (! $request instanceof Request) {
            return false;
        }

        return new self($this->inspector, $this->provider, $request)->user() instanceof Authenticatable;
    }

    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * A token carrying a subject authenticates that user and nobody else, so an unresolvable one is
     * rejected rather than falling back to the client. A userless token — `client_credentials`, or
     * an exchange without a subject — authenticates its client instead.
     */
    private function principalFor(AccessToken $token): ?Authenticatable
    {
        $userId = $token->getAttribute('user_id');

        if (is_string($userId)) {
            return $this->provider->retrieveById($userId);
        }

        $client = $token->client;

        return $client instanceof Client && ! $client->revoked ? new ClientPrincipal($client) : null;
    }

    /**
     * Named apart from GuardHelpers::authenticate(), which the Guard contract expects to take no
     * arguments and return a non-nullable Authenticatable, so it is not silently overridden.
     */
    private function verifyBearerToken(string $jwt): ?AccessToken
    {
        $parsed = $this->inspector->parse($jwt);

        if (! $parsed instanceof Plain || $parsed->headers()->get('typ') !== 'at+jwt') {
            return null;
        }

        $exp = $parsed->claims()->get('exp');
        $expiry = $exp instanceof DateTimeInterface ? $exp->getTimestamp() : (is_numeric($exp) ? (int) $exp : 0);

        if ($expiry <= time()) {
            return null;
        }

        $token = $this->inspector->tokenForParsed($parsed);

        if (! $token instanceof AccessToken || $token->getAttribute('revoked')) {
            return null;
        }

        $audience = $this->normalizeAudience($parsed->claims()->get('aud'));

        // Resolved per call, not held: the guard instance outlives a request (see setRequest),
        // while the realm it serves is resolved from the current one.
        if (! app(RealmAudiences::class)->accepts($audience)) {
            return null;
        }

        $this->request->attributes->set('oidc_token_audience', $audience);

        return $token;
    }

    /** @return list<string> */
    private function normalizeAudience(mixed $aud): array
    {
        return array_values(array_filter(is_array($aud) ? $aud : [$aud], is_string(...)));
    }
}
