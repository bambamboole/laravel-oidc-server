<?php

declare(strict_types=1);

$server = 'Bambamboole\LaravelOidc\Server';

/*
 * Every domain may use Shared. Anything beyond that must be listed here: the
 * cross-domain contracts live in Shared, so a new entry means a new coupling
 * that Shared could not express. Realms is the foundation Shared builds on,
 * Protocol is the OAuth/OIDC endpoint layer that composes everything below, and
 * Installation and Consents sit on top as orchestration. Testing is the
 * consumer-facing test kit and the root service provider wires all domains,
 * so neither is constrained.
 */
$dependencies = [
    'Shared' => [],
    'Realms' => [],
    'Audit' => [],
    'Keys' => [],
    'Credentials' => [],
    'Brokering' => [],
    'Clients' => [],
    'Scopes' => ['Clients'],
    'Tokens' => ['Clients', 'Scopes'],
    'Sessions' => ['Clients', 'Scopes'],
    'Authentication' => ['Clients', 'Tokens'],
    'Protocol' => ['Authentication', 'Clients', 'Scopes', 'Sessions', 'Tokens'],
    'Consents' => ['Clients', 'Scopes'],
    'Installation' => ['Clients', 'Keys'],
];

$domains = array_keys($dependencies);

foreach ($dependencies as $domain => $allowed) {
    $allowedWithShared = $domain === 'Shared' ? [] : ['Shared', ...$allowed];
    $forbidden = array_values(array_diff($domains, $allowedWithShared, [$domain]));

    arch("{$domain} only depends on ".($allowedWithShared === [] ? 'nothing' : implode(', ', $allowedWithShared)))
        ->expect("{$server}\\{$domain}")
        ->not->toUse(array_map(fn (string $forbiddenDomain): string => "{$server}\\{$forbiddenDomain}", $forbidden))
        // The Client model owns its token relations; that is the one edge back into Tokens.
        ->ignoring($domain === 'Clients' ? ["{$server}\\Tokens\\Models\\Token", "{$server}\\Tokens\\Models\\AuthCode"] : []);
}
