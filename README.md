# laravel-oidc-server

An **OIDC-capable auth server built as a Laravel package** — turn your Laravel app into a
full OpenID Connect identity provider that other applications authenticate their users
against.

This is the server package of the
[`laravel-oidc`](https://github.com/bambamboole/laravel-oidc) monorepo. Its siblings are
[`bambamboole/laravel-oidc-client`](https://github.com/bambamboole/laravel-oidc-client)
(the relying party) and
[`bambamboole/laravel-oidc-ui`](https://github.com/bambamboole/laravel-oidc-ui)
(the Lattice auth UI); `bambamboole/laravel-oidc` ships all three.

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
- Laravel 13

## Installation

Install the server package on its own, or the full suite (server + client + ui) via
`composer require bambamboole/laravel-oidc`:

```bash
composer require bambamboole/laravel-oidc-server

# Publish and run the migrations
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

## A package-owned OAuth2 core

The package implements the OAuth 2.1 / OpenID Connect core itself: client authentication, the
authorization request, authorization codes with PKCE, refresh-token rotation, and the token
endpoint's grants live in the `Protocol` domain on top of the package's own tables and models.
This means:

- The authorization, token and approve/deny routes are registered by this package using its own
  controllers, so `max_age`, `prompt`, OIDC scopes and the `id_token` are wired in.
- **PKCE with `S256` is required on every authorization request**, per OAuth 2.1 §4.1.1/§7.6 —
  for confidential clients as well as public ones. A request missing it is answered with an
  `invalid_request` error on the client's redirect URI.
- Authorization codes and refresh tokens are opaque, single-use database records. A replayed code
  or a reused refresh token revokes every token that descends from it.
- The signing key is read on every request, so a key rotation takes effect without restarting
  the workers.
- No client-management JSON API ships with the package. Provision clients with
  `oidc:provision-client`, or through dynamic client registration.

## Documentation

The full documentation lives at **[bambamboole.github.io/laravel-oidc](https://bambamboole.github.io/laravel-oidc)**.
It is built with [Starlight](https://starlight.astro.build/) from the `docs/` directory of
the [monorepo](https://github.com/bambamboole/laravel-oidc), where `npm run docs:dev`
serves it locally.

## Testing

The suite runs from the root of the
[monorepo](https://github.com/bambamboole/laravel-oidc), which holds the single Composer
install for all packages:

```bash
composer install
composer check   # pint --test, phpstan (level 6), rector --dry-run, and the pest suite
```

CI runs the suite on Laravel 13 on every push and pull request.

## Changelog

All packages in the suite are versioned in lockstep; see the
[monorepo changelog](https://github.com/bambamboole/laravel-oidc/blob/main/CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
