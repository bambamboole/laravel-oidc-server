<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

use Bambamboole\LaravelOidc\Server\Realms\Enums\RealmRouting;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;

/**
 * The configured issuer supplies the origin. Below `/realms/{realm}` every
 * realm is its own OpenID Provider with its own issuer; a single-realm
 * deployment is the origin itself. In `domain` routing the realm's own host
 * is the origin, taken from the current request and, outside one, from the
 * host mapped to the realm in `oidc.routes.domains`.
 *
 * `oidc.issuer` is an origin without a path. Routes are registered at the
 * application root, so a path in the issuer would only be carried into the
 * discovery document and name endpoints that answer 404.
 */
final readonly class RealmIssuerResolver implements IssuerResolver
{
    public function __construct(
        private RealmResolver $realms,
        private RealmRepository $repository,
    ) {}

    public function url(): string
    {
        $routing = RealmRouting::configured();
        $realm = $this->realms->current()->id();

        if ($routing === RealmRouting::Domain) {
            return $this->realmOrigin($realm);
        }

        return $this->configuredOrigin().$routing->issuerPath($realm);
    }

    /**
     * The request supplies the origin only when it actually arrived on this
     * realm's host. A queued job's request is built from `app.url`, so its
     * host belongs to another realm or to none, and the origin has to come
     * from the map instead — with the scheme from the configured issuer,
     * which is all it contributes in this mode.
     */
    private function realmOrigin(string $realm): string
    {
        $request = request();
        $host = $request->getHost();

        if ($host !== '' && $this->repository->findByDomain($host)?->id() === $realm) {
            return rtrim($request->getSchemeAndHttpHost(), '/');
        }

        $domain = array_search($realm, (array) config('oidc.routes.domains', []), true);

        return is_string($domain)
            ? (parse_url($this->configuredOrigin(), PHP_URL_SCHEME) ?: 'https').'://'.$domain
            : $this->configuredOrigin();
    }

    private function configuredOrigin(): string
    {
        return rtrim((string) (config('oidc.issuer') ?: config('app.url')), '/');
    }
}
