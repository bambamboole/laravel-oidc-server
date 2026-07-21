<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Social;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use phpseclib3\Crypt\PublicKeyLoader;
use Throwable;

/**
 * Generic driver for any OIDC-compliant upstream IdP: endpoints come from the
 * discovery document, and the id_token is verified against the upstream JWKS.
 */
class OidcProvider extends AbstractOAuth2Provider
{
    private const int METADATA_CACHE_TTL = 3600;

    protected function usesNonce(): bool
    {
        return true;
    }

    protected function issuer(): string
    {
        return rtrim((string) ($this->config['issuer'] ?? ''), '/');
    }

    protected function authorizationEndpoint(): string
    {
        return (string) $this->discovery()['authorization_endpoint'];
    }

    protected function tokenEndpoint(): string
    {
        return (string) $this->discovery()['token_endpoint'];
    }

    /**
     * @return list<string>
     */
    protected function defaultScopes(): array
    {
        return ['openid', 'profile', 'email'];
    }

    protected function fetchUser(TokenResponse $tokens, PendingAuthorization $pending, Request $request): SocialUser
    {
        if ($tokens->idToken === null) {
            throw new SocialAuthenticationException("The [{$this->key}] token response did not include an id_token.");
        }

        $claims = $this->verifiedIdTokenClaims($tokens->idToken, $pending->nonce);

        $userinfoEndpoint = $this->discovery()['userinfo_endpoint'] ?? null;

        if ((! isset($claims['email']) || ! isset($claims['name'])) && is_string($userinfoEndpoint) && $tokens->accessToken !== null) {
            $userinfo = Http::withToken($tokens->accessToken)->acceptJson()->get($userinfoEndpoint);

            if ($userinfo->successful()) {
                // id_token claims win over userinfo on conflict.
                $claims = array_merge((array) $userinfo->json(), $claims);
            }
        }

        return new SocialUser(
            id: (string) $claims['sub'],
            email: is_string($claims['email'] ?? null) ? $claims['email'] : null,
            emailVerified: filter_var($claims['email_verified'] ?? false, FILTER_VALIDATE_BOOL),
            name: is_string($claims['name'] ?? null) ? $claims['name'] : null,
            nickname: is_string($claims['preferred_username'] ?? null) ? $claims['preferred_username'] : null,
            avatar: is_string($claims['picture'] ?? null) ? $claims['picture'] : null,
            raw: $claims,
            accessToken: $tokens->accessToken,
            refreshToken: $tokens->refreshToken,
            expiresIn: $tokens->expiresIn,
            idToken: $tokens->idToken,
        );
    }

    /**
     * @return array<string, mixed>
     */
    protected function discovery(): array
    {
        return Cache::remember(
            "oidc.social.discovery.{$this->key}",
            self::METADATA_CACHE_TTL,
            function (): array {
                $response = Http::acceptJson()->get($this->issuer().'/.well-known/openid-configuration');

                if ($response->failed()) {
                    throw new SocialAuthenticationException("The [{$this->key}] discovery document could not be fetched (HTTP {$response->status()}).");
                }

                return (array) $response->json();
            },
        );
    }

    /**
     * @return array<string, mixed>
     */
    protected function verifiedIdTokenClaims(string $idToken, ?string $nonce): array
    {
        try {
            $token = (new Parser(new JoseEncoder))->parse($idToken);
        } catch (Throwable $exception) {
            throw new SocialAuthenticationException("The [{$this->key}] id_token could not be parsed: {$exception->getMessage()}");
        }

        assert($token instanceof Plain);

        $kid = $token->headers()->get('kid');

        $valid = new Validator()->validate(
            $token,
            new SignedWith(new Sha256, InMemory::plainText($this->signingKeyPem(is_string($kid) ? $kid : null))),
            new IssuedBy($this->issuer()),
            new PermittedFor((string) $this->config['client_id']),
            new LooseValidAt(SystemClock::fromSystemTimezone()),
        );

        if (! $valid) {
            throw new SocialAuthenticationException("The [{$this->key}] id_token failed validation.");
        }

        $claims = $token->claims()->all();

        if ($nonce !== null && ($claims['nonce'] ?? null) !== $nonce) {
            throw new SocialAuthenticationException("The [{$this->key}] id_token nonce does not match.");
        }

        return $claims;
    }

    private function signingKeyPem(?string $kid): string
    {
        /** @var list<array<string, mixed>> $keys */
        $keys = Cache::remember(
            "oidc.social.jwks.{$this->key}",
            self::METADATA_CACHE_TTL,
            function (): array {
                $response = Http::acceptJson()->get((string) $this->discovery()['jwks_uri']);

                if ($response->failed()) {
                    throw new SocialAuthenticationException("The [{$this->key}] JWKS could not be fetched (HTTP {$response->status()}).");
                }

                return (array) $response->json('keys', []);
            },
        );

        foreach ($keys as $jwk) {
            if (($jwk['kty'] ?? null) !== 'RSA') {
                continue;
            }

            if ($kid !== null && ($jwk['kid'] ?? null) !== $kid) {
                continue;
            }

            return PublicKeyLoader::load((string) json_encode($jwk))->toString('PKCS8');
        }

        throw new SocialAuthenticationException("No JWKS key matches the [{$this->key}] id_token.");
    }
}
