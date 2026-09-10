<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

use Bambamboole\LaravelOidc\Server\Realms\Enums\RealmRouting;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;

/**
 * The configured issuer supplies the origin. Below `/realms/{realm}` every
 * realm is its own OpenID Provider with its own issuer; a single-realm
 * deployment is the origin itself. In `domain` routing the realm's own host
 * is the origin, taken from the current request and, outside one, from the
 * host mapped to the realm in `oidc.routes.domains`.
 */
final readonly class RealmIssuerResolver implements IssuerResolver
{
    public function __construct(private RealmResolver $realms) {}

    public function url(): string
    {
        $routing = RealmRouting::configured();
        $realm = $this->realms->current()->id();

        if ($routing === RealmRouting::Domain) {
            return $this->realmOrigin($realm);
        }

        return $this->configuredOrigin().$routing->issuerPath($realm);
    }

    private function realmOrigin(string $realm): string
    {
        $request = request();
        $host = $request->getHost();

        if ($host !== '') {
            return rtrim($request->getSchemeAndHttpHost(), '/');
        }

        $domain = array_search($realm, (array) config('oidc.routes.domains', []), true);

        return is_string($domain)
            ? rtrim((string) parse_url($this->configuredOrigin(), PHP_URL_SCHEME) ?: 'https', '/').'://'.$domain
            : $this->configuredOrigin();
    }

    private function configuredOrigin(): string
    {
        return rtrim((string) (config('oidc.issuer') ?: config('app.url')), '/');
    }
}
