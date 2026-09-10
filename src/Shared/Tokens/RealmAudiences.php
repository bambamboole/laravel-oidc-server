<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Tokens;

use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;

/**
 * The resource identifiers a realm serves: its `tokens.audiences` setting
 * (the issuer URL when unset) plus the identifier of every protected
 * resource advertised through RFC 9728 metadata. An access token minted
 * without an explicit audience is addressed to all of them, and a bearer
 * token is accepted at the realm's resources only when its `aud` names one
 * of them (RFC 9068 §2.2, §4).
 */
final readonly class RealmAudiences
{
    public function __construct(
        private RealmResolver $realms,
        private IssuerResolver $issuer,
    ) {}

    /** @return list<string> */
    public function all(): array
    {
        $configured = $this->realms->current()->tokens()->audiences;
        $resources = array_map($this->protectedResource(...), $this->protectedResourcePaths());

        return array_values(array_unique([
            ...($configured !== [] ? $configured : [$this->issuer->url()]),
            ...$resources,
        ]));
    }

    /** @param  list<string>  $audience */
    public function accepts(array $audience): bool
    {
        return array_intersect($audience, $this->all()) !== [];
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

    /** @return list<string> */
    private function protectedResourcePaths(): array
    {
        return array_map(strval(...), array_keys((array) config('oidc.protected_resources', [])));
    }
}
