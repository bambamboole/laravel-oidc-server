<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;

/**
 * Turns the scopes a request asked for into the scopes a token gets: the
 * wildcard survives only for grants that mint tokens without a consent
 * screen, unknown scopes are dropped, the client's allow-list applies, and
 * the ScopeRepository has the final say.
 */
final class ScopeGrant
{
    private const array WILDCARD_GRANTS = ['personal_access', 'client_credentials'];

    public function __construct(private readonly ScopeRepository $scopes) {}

    /**
     * @param  list<string>  $requested
     * @return list<string>
     */
    public function finalize(array $requested, string $grantType, ?Client $client, ?string $userIdentifier = null): array
    {
        $ids = array_values(array_unique($requested));

        if (! in_array($grantType, self::WILDCARD_GRANTS, true)) {
            $ids = array_values(array_filter($ids, fn (string $id): bool => $id !== '*'));
        }

        if ($client !== null) {
            $ids = array_values(array_filter($ids, fn (string $id): bool => $client->hasScope($id)));
        }

        $wildcard = in_array('*', $ids, true);

        $candidates = array_values(array_filter(array_map(
            fn (string $id): ?Scope => $this->scopes->find($id),
            $ids,
        )));

        $finalized = array_map(
            fn (Scope $scope): string => $scope->id,
            $this->scopes->finalize($candidates, $grantType, $client, $userIdentifier),
        );

        return array_values($wildcard ? ['*', ...$finalized] : $finalized);
    }
}
