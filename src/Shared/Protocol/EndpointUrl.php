<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Protocol;

use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;

/**
 * The absolute URL of one of the package's routes for the current realm.
 * Endpoint paths already carry the realm, so they are hung off the issuer's
 * origin rather than the issuer itself; rebuilding from the issuer rather
 * than the request keeps a forwarded host out of metadata documents
 * (RFC 8414 §3) and bearer challenges (RFC 9728 §5.1).
 */
final readonly class EndpointUrl
{
    public function __construct(
        private IssuerResolver $issuer,
        private RealmResolver $realms,
    ) {}

    public function of(string $routeName): string
    {
        $path = parse_url(route($routeName, ['realm' => $this->realms->current()->identifier()]), PHP_URL_PATH);

        return $this->origin().($path ?? '');
    }

    private function origin(): string
    {
        $issuer = rtrim($this->issuer->url(), '/');
        $parts = parse_url($issuer);

        if (! isset($parts['scheme'], $parts['host'])) {
            return $issuer;
        }

        $port = isset($parts['port']) ? ':'.$parts['port'] : '';

        return $parts['scheme'].'://'.$parts['host'].$port;
    }
}
