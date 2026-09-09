<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

/**
 * Scopes registered at runtime through `Oidc::tokensCan()`, merged into the
 * catalog behind the configured `oidc.scopes.catalog` entries.
 */
final class ScopeRegistry
{
    /** @var array<string, string> */
    private static array $scopes = [];

    /** @param  array<string, string>  $scopes */
    public static function tokensCan(array $scopes): void
    {
        self::$scopes = $scopes;
    }

    /** @return array<string, string> */
    public static function all(): array
    {
        return self::$scopes;
    }

    public static function flush(): void
    {
        self::$scopes = [];
    }
}
