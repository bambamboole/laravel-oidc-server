<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Tokens;

use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;

/**
 * The resource identifiers a realm serves. The realm itself is identified
 * by its issuer URL, which is the default audience of every access token
 * minted without an RFC 8707 `resource` (RFC 9068 §3); the resources it
 * registers on top (`oidc.resources`) are further audiences a client may
 * request and the bearer guard accepts (RFC 9068 §4). A path-relative
 * resource is published through RFC 9728 metadata.
 */
final readonly class RealmAudiences
{
    public function __construct(
        private RealmResolver $realms,
        private IssuerResolver $issuer,
    ) {}

    /** @return list<string> */
    public function default(): array
    {
        return [$this->issuer->url()];
    }

    /** @return list<string> */
    public function all(): array
    {
        return array_values(array_unique([
            $this->issuer->url(),
            ...array_map($this->identifier(...), array_keys($this->realms->current()->resources()->resources)),
        ]));
    }

    /** @param  list<string>  $audience */
    public function accepts(array $audience): bool
    {
        return array_intersect($audience, $this->all()) !== [];
    }

    /**
     * The scopes a path-relative resource advertises; null when no such
     * resource is registered under the path.
     *
     * @return list<string>|null
     */
    public function advertisedScopes(string $path): ?array
    {
        $resources = $this->realms->current()->resources()->resources;
        $path = trim($path, '/');

        foreach ($resources as $identifier => $scopes) {
            if (! $this->isAbsolute($identifier) && trim($identifier, '/') === $path) {
                return $scopes;
            }
        }

        return null;
    }

    /**
     * RFC 9728 §3.3: a protected resource declared under a path relative to
     * the issuer is identified by the issuer URL with that path appended.
     */
    public function protectedResource(string $path): string
    {
        $path = trim($path, '/');
        $issuer = $this->issuer->url();

        return $path === '' ? $issuer : $issuer.'/'.$path;
    }

    private function identifier(string $resource): string
    {
        return $this->isAbsolute($resource) ? $resource : $this->protectedResource($resource);
    }

    private function isAbsolute(string $resource): bool
    {
        return parse_url($resource, PHP_URL_SCHEME) !== null;
    }
}
