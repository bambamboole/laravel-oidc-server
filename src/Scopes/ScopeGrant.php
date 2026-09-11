<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes;

use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Scopes\Contracts\ScopeRepository;

/**
 * Turns the scopes a request asked for into the scopes a token gets. Grants
 * that mint without a consent screen and without an earlier artifact bounding
 * them keep the wildcard and receive the client's default scopes; every other
 * grant already carries its defaults from the authorize request, the original
 * token or the subject token. Unknown scopes, scopes outside the client's
 * assignment and scopes no requested resource owns are dropped, and the
 * ScopeRepository has the final say.
 */
final readonly class ScopeGrant
{
    private const array UNBOUNDED_GRANTS = ['personal_access', 'client_credentials'];

    public function __construct(private ScopeRepository $scopes) {}

    /**
     * @param  list<string>  $requested
     * @param  list<string>  $audiences  the resources the token is for; empty for the realm default
     * @return list<string>
     */
    public function finalize(array $requested, string $grantType, ?Client $client, ?string $userIdentifier = null, array $audiences = []): array
    {
        $ids = array_values(array_unique($requested));

        if (! in_array($grantType, self::UNBOUNDED_GRANTS, true)) {
            $ids = array_values(array_filter($ids, fn (string $id): bool => $id !== '*'));
        } elseif ($client instanceof Client) {
            $ids = array_values(array_unique([...$ids, ...$client->defaultScopes($audiences)]));
        }

        if ($client instanceof Client) {
            $ids = array_values(array_filter($ids, fn (string $id): bool => $client->allowsScope($id, $audiences)));
        }

        $wildcard = in_array('*', $ids, true);

        $candidates = array_values(array_filter(array_map(
            fn (string $id): ?Scope => $this->scopes->find($id, $audiences),
            $ids,
        )));

        $finalized = array_map(
            fn (Scope $scope): string => $scope->id,
            $this->scopes->finalize($candidates, $grantType, $client, $userIdentifier, $audiences),
        );

        return array_values($wildcard ? ['*', ...$finalized] : $finalized);
    }
}
