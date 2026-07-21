# laravel-oidc

An **OIDC-capable auth server built as a Laravel package** — turn your Laravel app into a
full OpenID Connect identity provider that other applications authenticate their users
against.

The package provides the complete protocol surface of an identity provider and, optionally,
a complete authentication engine (login, registration, MFA) that your app fills with its own
views and actions.

📖 **[Read the documentation →](https://bambamboole.github.io/laravel-oidc)**

## What you get

**OIDC provider**

- Signed RS256 `id_token`s, a `/.well-known/openid-configuration` discovery document, and a
  JWKS endpoint (RFC 7638 `kid`s).
- `userinfo`, RP-initiated logout, OIDC **back-channel logout**, RFC 7662 introspection, and
  RFC 7009 revocation.
- **RFC 9068** structured `at+jwt` access tokens.
- **RFC 8693** token exchange, with a self-contained `CheckAudience` resource-server middleware.
- Capability-scoped token triggers and a swappable `ClaimsResolver` / `ScopeRepository` / `ExchangePolicy`.
- Env-based signing keys (`OIDC_PRIVATE_KEY` / `OIDC_PUBLIC_KEY`) with a built-in rotation
  command.

**Auth engine** (optional)

- Package-owned login, registration, password reset, email verification, and password
  confirmation, driven by view and action *seams* your app fills.
- Multi-factor authentication: TOTP, recovery codes, and passkeys (WebAuthn).
- A post-login pipeline with a single decision hook (`requireMfa` / `deny` / add claims) and
  `acr` / `amr` emission.

## Requirements

- PHP `^8.4`
- Laravel 11, 12, or 13
- `laravel/passport` `^13.4` — the OAuth2 core the package builds on

## Installation

```bash
composer require bambamboole/laravel-oidc

# Publish and run the migrations (extends oauth_clients + adds the package's own tables)
php artisan vendor:publish --tag=oidc-migrations
php artisan migrate

# Generate env-based, rotatable RSA signing keys (OIDC_PRIVATE_KEY / OIDC_PUBLIC_KEY)
php artisan oidc:rotate-keys

# Optional: publish the config
php artisan vendor:publish --tag=oidc-config
```

The service provider is auto-discovered. Set `OIDC_ISSUER` to your provider's public origin —
every URL advertised in discovery is derived from it.

See the **[Installation guide](https://bambamboole.github.io/laravel-oidc/introduction/installation/)**
for the full walkthrough, and **[Configuration](https://bambamboole.github.io/laravel-oidc/introduction/configuration/)**
for every `config/oidc.php` key.

## Built on Passport

Under the hood, the OAuth2 core is **Laravel Passport 13** — the package extends and
reconfigures it rather than reimplementing an authorization server. On registration it calls
`Passport::ignoreRoutes()` and registers the full `/oauth/*` route surface itself, so that:

- OIDC scopes, `max_age`, and the `id_token` response type are wired in.
- **PKCE is required on every authorization request** (OAuth 2.1 §4.1.1/§7.6), for confidential
  clients too.
- Passport's optional JSON API management routes are **not** registered — register them
  yourself if you need them.
- The access-token entity is swapped to `OidcAccessToken` and the response type to
  `IdTokenResponse`.

## Documentation

The full documentation lives at **[bambamboole.github.io/laravel-oidc](https://bambamboole.github.io/laravel-oidc)**
and is built with [Starlight](https://starlight.astro.build/). To run it locally:

```bash
npm install
npm run docs:dev
```

## Testing

```bash
composer check   # pint --test, phpstan (level 6), and the pest suite
```

CI runs the suite across Laravel 11/12/13 on every push and pull request.

## License

MIT. See [LICENSE](LICENSE).
