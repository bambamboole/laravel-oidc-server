<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth;

/**
 * Typed owner of the OIDC session keys written during interactive login: the
 * amr method list, the buffered id/access-token claims from the postLogin
 * pipeline, and the sid/auth_time pair recorded when an OIDC session starts.
 */
final class AuthSessionState
{
    public const string AMR_KEY = 'oidc.amr';

    private const string ID_TOKEN_CLAIMS_KEY = 'oidc.id_token_claims';

    private const string ACCESS_TOKEN_CLAIMS_KEY = 'oidc.access_token_claims';

    private const string AUTH_TIME_KEY = 'oidc.auth_time';

    private const string SID_KEY = 'oidc.sid';

    private const string REQUESTED_ACR_VALUES_KEY = 'oidc.requested_acr_values';

    public function start(string $method): void
    {
        session()->put(self::AMR_KEY, $this->dedupe([$method]));
    }

    public function add(string ...$methods): void
    {
        session()->put(self::AMR_KEY, $this->dedupe([...$this->amr(), ...$methods]));
    }

    /**
     * @return list<string>
     */
    public function amr(): array
    {
        $amr = session()->get(self::AMR_KEY, []);

        return is_array($amr) ? array_values(array_filter($amr, is_string(...))) : [];
    }

    /**
     * @param  array<string, mixed>  $idToken
     * @param  array<string, mixed>  $accessToken
     */
    public function putClaims(array $idToken, array $accessToken): void
    {
        session()->put([
            self::ID_TOKEN_CLAIMS_KEY => $idToken,
            self::ACCESS_TOKEN_CLAIMS_KEY => $accessToken,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    public function idTokenClaims(): array
    {
        $claims = session()->get(self::ID_TOKEN_CLAIMS_KEY, []);

        return is_array($claims) ? $claims : [];
    }

    /**
     * @return array<string, mixed>
     */
    public function accessTokenClaims(): array
    {
        $claims = session()->get(self::ACCESS_TOKEN_CLAIMS_KEY, []);

        return is_array($claims) ? $claims : [];
    }

    /**
     * League's AuthorizationRequestInterface has no acr accessor, so the raw
     * acr_values query param is stashed here at authorize time for the
     * post-login pipeline. An empty list clears the key — each authorize
     * request syncs it, so values never outlive the flow that requested them.
     *
     * @param  list<string>  $values
     */
    public function putRequestedAcrValues(array $values): void
    {
        if ($values === []) {
            session()->forget(self::REQUESTED_ACR_VALUES_KEY);

            return;
        }

        session()->put(self::REQUESTED_ACR_VALUES_KEY, $values);
    }

    /**
     * @return list<string>
     */
    public function requestedAcrValues(): array
    {
        $values = session()->get(self::REQUESTED_ACR_VALUES_KEY, []);

        return is_array($values) ? array_values(array_filter($values, is_string(...))) : [];
    }

    public function startOidcSession(string $sid): void
    {
        session()->put([
            self::AUTH_TIME_KEY => time(),
            self::SID_KEY => $sid,
        ]);
    }

    public function putAuthTime(int $authTime): void
    {
        session()->put(self::AUTH_TIME_KEY, $authTime);
    }

    public function sid(): ?string
    {
        $sid = session()->get(self::SID_KEY);

        return is_string($sid) && $sid !== '' ? $sid : null;
    }

    public function authTime(): ?int
    {
        $authTime = session()->get(self::AUTH_TIME_KEY);

        return is_numeric($authTime) ? (int) $authTime : null;
    }

    /**
     * Clears the login-derived state (amr + buffered claims). The sid and
     * auth_time survive: they describe the OIDC session, not a single login
     * attempt, and are torn down with the session itself.
     */
    public function forget(): void
    {
        session()->forget([self::AMR_KEY, self::ID_TOKEN_CLAIMS_KEY, self::ACCESS_TOKEN_CLAIMS_KEY]);
    }

    /**
     * @param  list<string>  $amr
     */
    public static function deriveAcr(array $amr): ?string
    {
        if ($amr === []) {
            return null;
        }

        return count($amr) > 1 ? '2' : '1';
    }

    /**
     * @param  array<int, mixed>  $methods
     * @return list<string>
     */
    private function dedupe(array $methods): array
    {
        return array_values(array_unique(array_filter($methods, is_string(...))));
    }
}
