<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\MultiFactor\RecoveryCodeProvider;
use Bambamboole\LaravelOidc\Auth\MultiFactor\TotpFactorProvider;
use Bambamboole\LaravelOidc\Auth\MultiFactor\WebAuthnFactorProvider;

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

    'api_guard' => env('OIDC_API_GUARD', 'api'),

    'claims_supported' => [
        'iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'at_hash', 'azp',
        'name', 'email', 'email_verified', 'locale', 'zoneinfo', 'updated_at',
    ],

    'token_exchange' => [
        'enabled' => env('OIDC_TOKEN_EXCHANGE_ENABLED', true),
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
    ],

    'auth' => [
        'guard' => env('OIDC_AUTH_GUARD', 'identity'),
        'provider' => env('OIDC_AUTH_PROVIDER', 'users'),
        'home' => env('OIDC_AUTH_HOME', '/dashboard'),
        'username' => env('OIDC_AUTH_USERNAME', 'email'),
        'two_factor' => [
            'challenge_providers' => ['totp'],
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
