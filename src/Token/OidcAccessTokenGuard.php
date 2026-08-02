<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Token;

use Bambamboole\LaravelOidc\Server\Http\Middleware\CheckAudience;
use Bambamboole\LaravelOidc\Server\Issuer;
use DateTimeInterface;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;
use Laravel\Passport\AccessToken;
use Laravel\Passport\Token;

/**
 * Purpose-built `auth:oidc` guard: a self-contained RFC 9068 resource-server validator (signature,
 * `at+jwt` typ, expiry, revocation via {@see TokenInspector}) that accepts a bearer token when its
 * `aud` intersects {issuer URL, configured `oidc.resource.audiences`} OR carries the token's own
 * `client_id` claim — the latter is what makes classic (non-exchanged) tokens pass uniformly, since
 * {@see OidcAccessToken::convertToJWT()} defaults `aud` to `[$clientId]` and always sets `client_id`.
 * The verified audience is stashed on the request for {@see CheckAudience}
 * to read back without re-parsing the token.
 *
 * The user provider comes from this guard's own `auth.guards.{name}.provider` config entry (handed
 * in by `Auth::extend()`), not from {@see ResolvesTokenUser} — that trait resolves via
 * `passport.guard`'s provider instead, which is this package's *identity* guard, not necessarily
 * the one configured for this guard.
 */
class OidcAccessTokenGuard implements Guard
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

        if ($token === null) {
            return null;
        }

        $userId = $token->getAttribute('user_id');
        $user = is_string($userId) ? $this->provider->retrieveById($userId) : null;

        if ($user === null) {
            return null;
        }

        $accessToken = new AccessToken([
            'oauth_access_token_id' => $token->getKey(),
            'oauth_client_id' => $token->getAttribute('client_id'),
            'oauth_user_id' => $userId,
            'oauth_scopes' => $token->getAttribute('scopes') ?? [],
        ]);

        return $this->user = $user->withAccessToken($accessToken);
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

        return (new self($this->inspector, $this->provider, $request))->user() !== null;
    }

    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Full RFC 9068 validation, then the audience gate described in the class docblock. Named apart
     * from GuardHelpers::authenticate() (which the Guard/Auth facade contract expects to take no
     * arguments and return a non-nullable Authenticatable) to avoid silently overriding it.
     */
    private function verifyBearerToken(string $jwt): ?Token
    {
        $parsed = $this->inspector->parse($jwt);

        if ($parsed === null || $parsed->headers()->get('typ') !== 'at+jwt') {
            return null;
        }

        $exp = $parsed->claims()->get('exp');
        $expiry = $exp instanceof DateTimeInterface ? $exp->getTimestamp() : (is_numeric($exp) ? (int) $exp : 0);

        if ($expiry <= time()) {
            return null;
        }

        $token = $this->inspector->tokenForParsed($parsed);

        if ($token === null || $token->getAttribute('revoked')) {
            return null;
        }

        $audience = $this->normalizeAudience($parsed->claims()->get('aud'));
        $clientId = $parsed->claims()->get('client_id');
        $accepted = [Issuer::url(), ...$this->configuredAudiences()];

        if (array_intersect($audience, $accepted) === [] && ! (is_string($clientId) && in_array($clientId, $audience, true))) {
            return null;
        }

        $this->request->attributes->set('oidc_token_audience', $audience);

        return $token;
    }

    /** @return string[] */
    private function normalizeAudience(mixed $aud): array
    {
        return array_values(array_filter(is_array($aud) ? $aud : [$aud], 'is_string'));
    }

    /** @return string[] */
    private function configuredAudiences(): array
    {
        return array_values(array_filter((array) config('oidc.resource.audiences', []), 'is_string'));
    }
}
