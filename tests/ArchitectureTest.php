<?php

declare(strict_types=1);

$server = 'Bambamboole\LaravelOidc\Server';

/*
 * Each domain may only depend on the domains listed for it. Realms is the
 * foundation, Shared holds the cross-domain primitives on top of it, Protocol
 * is the league adapter that composes everything below, and Installation and
 * Consents sit on top as orchestration. Testing is the consumer-facing test kit
 * and the root service provider wires all domains, so neither is constrained.
 */
$dependencies = [
    'Realms' => [],
    'Shared' => ['Realms'],
    'Audit' => ['Shared'],
    'Keys' => ['Audit', 'Realms', 'Shared'],
    'Clients' => ['Audit', 'Realms', 'Shared'],
    'Credentials' => ['Audit', 'Realms', 'Shared'],
    'Scopes' => ['Clients', 'Realms', 'Shared'],
    'Tokens' => ['Audit', 'Clients', 'Keys', 'Realms', 'Scopes', 'Shared'],
    'Users' => ['Clients', 'Tokens'],
    'Sessions' => ['Clients', 'Keys', 'Realms', 'Scopes', 'Shared', 'Tokens'],
    'Authentication' => ['Audit', 'Clients', 'Credentials', 'Realms', 'Sessions', 'Shared', 'Tokens', 'Users'],
    'Brokering' => ['Audit', 'Authentication', 'Realms', 'Shared'],
    'Protocol' => ['Audit', 'Authentication', 'Clients', 'Keys', 'Realms', 'Scopes', 'Sessions', 'Shared', 'Tokens', 'Users'],
    'Consents' => ['Audit', 'Clients', 'Protocol', 'Scopes', 'Shared'],
    'Installation' => ['Clients', 'Keys', 'Shared'],
];

$domains = array_keys($dependencies);

foreach ($dependencies as $domain => $allowed) {
    $forbidden = array_values(array_diff($domains, $allowed, [$domain]));

    arch("{$domain} only depends on ".($allowed === [] ? 'nothing' : implode(', ', $allowed)))
        ->expect("{$server}\\{$domain}")
        ->not->toUse(array_map(fn (string $forbiddenDomain): string => "{$server}\\{$forbiddenDomain}", $forbidden))
        // The Client model owns its token relations; that is the one edge back into Tokens.
        ->ignoring($domain === 'Clients' ? ["{$server}\\Tokens\\Models\\Token", "{$server}\\Tokens\\Models\\AuthCode"] : []);
}

arch('league/oauth2-server stays inside Protocol')
    ->expect($server)
    ->not->toUse('League\OAuth2\Server')
    ->ignoring([
        "{$server}\\Protocol",
        "{$server}\\Consents\\Actions\\CompleteAuthorization",
        "{$server}\\Tokens\\TokenInspector",
    ]);
