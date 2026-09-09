<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Http;

final class RedirectUri
{
    /**
     * Appends response parameters to a client's redirect URI, keeping any query
     * the registered URI already carries.
     *
     * @param  array<string, string>  $parameters
     */
    public static function append(string $uri, array $parameters): string
    {
        if ($parameters === []) {
            return $uri;
        }

        return $uri.(str_contains($uri, '?') ? '&' : '?').http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * OAuth 2.1 §4.1.3: registered and requested URIs must match character by
     * character; RFC 8252 §7.3 exempts the port of a loopback redirect.
     *
     * @param  list<string>  $registered
     */
    public static function matches(string $requested, array $registered): bool
    {
        foreach ($registered as $candidate) {
            if (hash_equals($candidate, $requested) || self::loopbackMatches($requested, $candidate)) {
                return true;
            }
        }

        return false;
    }

    private static function loopbackMatches(string $requested, string $registered): bool
    {
        $requestedParts = parse_url($requested);
        $registeredParts = parse_url($registered);

        if ($requestedParts === false || $registeredParts === false) {
            return false;
        }

        $host = $requestedParts['host'] ?? null;

        if (($requestedParts['scheme'] ?? null) !== 'http' || ! in_array($host, ['127.0.0.1', '[::1]'], true)) {
            return false;
        }

        unset($requestedParts['port'], $registeredParts['port']);

        return $requestedParts === $registeredParts;
    }
}
