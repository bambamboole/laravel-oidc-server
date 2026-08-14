<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Audit\LogSink;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\RecoveryCodeProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\TotpFactorProvider;
use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\WebAuthnFactorProvider;

return [
    'issuer' => env('OIDC_ISSUER'),

    // RS256 signing keypair as PEM strings (\n-escaped single lines are fine).
    // When unset, resolution falls back to passport.{private,public}_key and
    // finally Passport's oauth-{private,public}.key files.
    'private_key' => env('OIDC_PRIVATE_KEY'),
    'public_key' => env('OIDC_PUBLIC_KEY'),

    'token_lifetimes' => [
        // Interactive access token (authorization_code) + refreshed access tokens. Short, per industry.
        'access_token' => (int) env('OIDC_ACCESS_TOKEN_TTL', 900),
        'id_token' => (int) env('OIDC_ID_TOKEN_TTL', 3600),
        // Machine-to-machine (client_credentials): no refresh, no session; client re-requests. Own TTL.
        'client_credentials' => (int) env('OIDC_M2M_ACCESS_TOKEN_TTL', 3600),
    ],

    'session' => [
        // Absolute cap on an interactive session, from login. Refresh is denied past this and the user
        // must re-authenticate; refresh-token rotation cannot extend it. Drives context.expires_at,
        // the refresh deny-check, and context pruning. Idle cap = Passport::refreshTokensExpireIn().
        'absolute_lifetime' => (int) env('OIDC_SESSION_ABSOLUTE_LIFETIME', 2592000),
    ],

    'api_guard' => env('OIDC_API_GUARD', 'oidc'),

    'passport' => [
        // Eloquent token model handed to Passport::useTokenModel(); a
        // class-string of a Laravel\Passport\Token subclass. Null keeps
        // Passport's default model.
        'token_model' => null,

        // API scope catalog consulted by the scope repository at
        // enumeration time (consent, discovery, issuance): an inline
        // [scope => description] map, or the class-string of a ScopeCatalog
        // implementation resolved from the container. A catalog's scopes()
        // may hit the database — failures fall back to an empty catalog so
        // key- and db-less artisan runs never break; an invalid class-string
        // fails loudly at first enumeration.
        'scopes' => [],
    ],

    'claims_supported' => [
        'iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'at_hash', 'azp',
        'name', 'email', 'email_verified', 'locale', 'zoneinfo', 'updated_at',
    ],

    'token_exchange' => [
        'enabled' => env('OIDC_TOKEN_EXCHANGE_ENABLED', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit logging
    |--------------------------------------------------------------------------
    |
    | Every security-relevant event (logins, MFA, consent, token issuance,
    | revocation, client administration) is dispatched as an AuditEvent and
    | forwarded to the configured sink. `sink` is a class-string of an
    | AuditSink implementation resolved from the container; the shipped
    | LogSink writes structured log lines (failures as warning, successes as
    | info) to `log_channel`, null meaning the default channel. Recording is
    | fail-open: sink failures are reported, never propagated.
    |
    */
    'audit' => [
        'enabled' => env('OIDC_AUDIT_ENABLED', true),
        'sink' => LogSink::class,
        'log_channel' => env('OIDC_AUDIT_LOG_CHANNEL'),
    ],

    // Additional resource audiences the oidc guard accepts on an exchanged access token,
    // beyond the issuer URL. Only widens what's accepted — a foreign audience still 401s.
    'resource' => [
        'audiences' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Protected resource metadata (RFC 9728)
    |--------------------------------------------------------------------------
    |
    | Resources this provider protects, advertised via
    | `/.well-known/oauth-protected-resource/{path}`. Keys are the resource's
    | path relative to the issuer origin (no slashes); MCP clients resolve
    | their authorization server through this document. Unlisted paths 404.
    |
    | 'mcp' => ['scopes' => ['mcp:use']],
    |
    */
    'protected_resources' => [],

    /*
    |--------------------------------------------------------------------------
    | Dynamic client registration (RFC 7591)
    |--------------------------------------------------------------------------
    |
    | When enabled, `POST /oauth/register` lets clients (e.g. MCP clients such
    | as Claude or Cursor) register themselves without credentials. Registered
    | clients are always public (no secret) with PKCE enforced. Redirect URIs
    | must use http(s) — hosts checked against `allowed_redirect_domains`
    | ('*' allows any) — or one of the `allowed_redirect_schemes` (e.g.
    | 'claude', 'cursor', 'vscode'; a non-http scheme requires a host).
    | `default_scopes` restricts registered clients to those scopes; empty
    | leaves the client unrestricted (Passport default).
    |
    */
    'dcr' => [
        'enabled' => env('OIDC_DCR_ENABLED', false),
        'allowed_redirect_schemes' => [],
        'allowed_redirect_domains' => ['*'],
        'default_scopes' => [],
    ],

    'key_size' => (int) env('OIDC_KEY_SIZE', 2048),

    'additional_public_keys' => array_values(array_filter([
        str_replace('\n', "\n", (string) env('OIDC_PREVIOUS_PUBLIC_KEY', '')),
    ], static fn (string $pem): bool => trim($pem) !== '')),

    'logout_redirect' => '/',

    'first_party' => [
        'client_id' => env('OIDC_FIRST_PARTY_CLIENT') ?: null,
        'trusted' => env('OIDC_FIRST_PARTY_TRUSTED', false),

        // Extra provisioning metadata applied by `oidc:install-self` on top of
        // the APP_URL-derived defaults. Token exchange is only enabled on the
        // client when at least one audience is listed.
        'provision' => [
            'redirect_uris' => [],
            'post_logout_redirect_uris' => [],
            'allowed_exchange_audiences' => [],
        ],
    ],

    'trusted_clients' => [],

    'login_route' => env('OIDC_LOGIN_ROUTE', 'login'),

    'session_token' => [
        'ttl' => (int) env('OIDC_SESSION_TOKEN_TTL', 3600),
        'session_key' => 'oidc.session_token',
        'refresh_skew' => 60,
        'scopes' => null,
        // Guard whose login/logout owns the session token. Null falls back to
        // the OIDC auth guard (oidc.auth.guard), then the application's default
        // guard; other guards never mint or revoke.
        'guard' => env('OIDC_SESSION_TOKEN_GUARD'),
    ],

    'auth' => [
        'guard' => env('OIDC_AUTH_GUARD', 'identity'),
        'provider' => env('OIDC_AUTH_PROVIDER', 'users'),
        'home' => env('OIDC_AUTH_HOME', '/dashboard'),
        'username' => env('OIDC_AUTH_USERNAME', 'email'),
        'two_factor' => [
            'challenge_providers' => ['totp', 'webauthn'],
            'secret_length' => 16,
            'window' => 1,
            'recovery_codes' => 8,
        ],
        'factors' => [
            TotpFactorProvider::class,
            RecoveryCodeProvider::class,
            WebAuthnFactorProvider::class,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Social login
    |--------------------------------------------------------------------------
    |
    | Upstream identity providers users can authenticate with. A provider is
    | active only when its client_id is configured. `driver` selects the
    | implementation: google, apple, github, or the generic `oidc` driver for
    | any OIDC-compliant IdP (requires `issuer`). Register custom drivers via
    | Oidc::extendSocialProvider().
    |
    */
    'social' => [
        // Attach an upstream identity to an existing local user when the
        // provider reports a verified email that matches.
        'link_by_verified_email' => true,
        // Create a local user on first social login via the action registered
        // with Oidc::createUsersFromSocialUsing(). Without a registered
        // action, provisioning is effectively disabled.
        'auto_provision' => true,
        'providers' => [
            'google' => [
                'driver' => 'google',
                'client_id' => env('OIDC_SOCIAL_GOOGLE_CLIENT_ID'),
                'client_secret' => env('OIDC_SOCIAL_GOOGLE_CLIENT_SECRET'),
            ],
            'apple' => [
                'driver' => 'apple',
                'client_id' => env('OIDC_SOCIAL_APPLE_CLIENT_ID'),
                'team_id' => env('OIDC_SOCIAL_APPLE_TEAM_ID'),
                'key_id' => env('OIDC_SOCIAL_APPLE_KEY_ID'),
                'private_key' => env('OIDC_SOCIAL_APPLE_PRIVATE_KEY'),
            ],
            'github' => [
                'driver' => 'github',
                'client_id' => env('OIDC_SOCIAL_GITHUB_CLIENT_ID'),
                'client_secret' => env('OIDC_SOCIAL_GITHUB_CLIENT_SECRET'),
            ],
        ],
    ],

    'routes' => [
        'prefix' => '',
        'middleware' => [],
    ],

    'handlers' => [],
];
