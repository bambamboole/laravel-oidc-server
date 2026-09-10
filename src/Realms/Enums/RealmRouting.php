<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms\Enums;

use ValueError;

/**
 * Where realms appear in URLs. `single` serves the configured realm from the
 * application root, so the issuer is the bare origin; `path` serves every
 * realm below `/realms/{realm}` and gives each its own issuer.
 */
enum RealmRouting: string
{
    case Single = 'single';
    case Path = 'path';

    public const string SEGMENT = 'realms';

    public static function configured(): self
    {
        $mode = config('oidc.routes.realms', self::Single->value);

        return self::tryFrom(is_string($mode) ? $mode : '')
            ?? throw new ValueError('oidc.routes.realms must be "single" or "path".');
    }

    /** The route prefix every package route is registered below. */
    public function prefix(): string
    {
        return $this === self::Path ? self::SEGMENT.'/{realm}' : '';
    }

    /**
     * RFC 8414 §3.1 and RFC 9728 §3.1 insert the well-known segment ahead of
     * the issuer's path, so the realm follows the well-known segment there.
     */
    public function wellKnownSuffix(): string
    {
        return $this === self::Path ? self::SEGMENT.'/{realm}/' : '';
    }

    /** A route path pattern for the given package path, e.g. for middleware exceptions. */
    public function pattern(string $path): string
    {
        return $this === self::Path ? self::SEGMENT.'/*/'.$path : $path;
    }

    /** The URL path a realm's routes live below; the session cookie path in `path` mode. */
    public function path(string $realm): string
    {
        return $this === self::Path ? '/'.self::SEGMENT.'/'.$realm : '/';
    }

    /** What the realm adds to the issuer origin. */
    public function issuerPath(string $realm): string
    {
        return $this === self::Path ? '/'.self::SEGMENT.'/'.$realm : '';
    }
}
