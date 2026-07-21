<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Routing;

/**
 * The resolved configuration for a single {@see Handler}: where it lives, what
 * handles it, and the middleware it runs through.
 */
final class HandlerConfig
{
    /**
     * @param  string|array{0: class-string, 1: string}  $controller  An invokable controller class, or a [class, method] pair.
     * @param  array<int, string>  $middleware
     */
    public function __construct(
        public readonly string $route,
        public readonly string|array $controller,
        public readonly array $middleware,
    ) {}
}
