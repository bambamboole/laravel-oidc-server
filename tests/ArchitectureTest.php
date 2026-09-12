<?php

declare(strict_types=1);

$server = 'Bambamboole\LaravelOidc\Server';

/*
 * Every domain may use Shared. Anything beyond that must be listed here: the
 * cross-domain contracts live in Shared, so a new entry means a new coupling
 * that Shared could not express. Realms is the foundation Shared builds on,
 * Protocol is the OAuth/OIDC endpoint layer that composes everything below, and
 * Installation, Consents and Purge sit on top as orchestration. Three things
 * are deliberately unconstrained: Testing is the consumer-facing test kit,
 * Database holds the factories every domain's models point at and which point
 * back at those models, and the root service provider wires all domains.
 */
$dependencies = [
    'Shared' => [],
    'Realms' => [],
    'Audit' => [],
    'SigningKeys' => [],
    'Credentials' => [],
    'Brokering' => [],
    'Clients' => [],
    'Scopes' => ['Clients'],
    'Tokens' => ['Clients', 'Scopes'],
    'Sessions' => ['Clients', 'Scopes'],
    'Authentication' => ['Clients', 'Tokens'],
    'Protocol' => ['Authentication', 'Clients', 'Scopes', 'Sessions', 'Tokens'],
    'Consents' => ['Clients', 'Scopes'],
    'Installation' => ['Clients', 'SigningKeys'],
    'Purge' => ['Authentication', 'Brokering', 'Clients', 'Consents', 'Credentials', 'Sessions', 'SigningKeys', 'Tokens'],
];

$domains = array_keys($dependencies);

/*
 * A rule naming a namespace that resolves to no classes passes vacuously, so a
 * domain renamed without touching the map above would report green forever
 * while constraining nothing — and would drop out of every other domain's
 * forbidden list at the same time.
 */
it('names every domain the package ships', function () use ($domains): void {
    $directories = array_map(basename(...), glob(__DIR__.'/../src/*', GLOB_ONLYDIR) ?: []);

    $shipped = array_values(array_diff($directories, ['Database', 'Testing']));
    sort($shipped);

    $constrained = $domains;
    sort($constrained);

    expect($constrained)->toBe($shipped);
});

foreach ($dependencies as $domain => $allowed) {
    $allowedWithShared = $domain === 'Shared' ? [] : ['Shared', ...$allowed];
    $forbidden = array_values(array_diff($domains, $allowedWithShared, [$domain]));

    arch("{$domain} only depends on ".($allowedWithShared === [] ? 'nothing' : implode(', ', $allowedWithShared)))
        ->expect("{$server}\\{$domain}")
        ->not->toUse(array_map(fn (string $forbiddenDomain): string => "{$server}\\{$forbiddenDomain}", $forbidden));
}
