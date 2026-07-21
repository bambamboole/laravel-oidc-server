<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Claims;

final readonly class ClaimSet
{
    /** @param array<string, array<string, mixed>> $claimsByScope */
    public function __construct(private array $claimsByScope = []) {}

    /**
     * @param  string[]  $scopeIds
     * @return array<string, mixed>
     */
    public function forScopes(array $scopeIds): array
    {
        $claims = [];

        foreach ($scopeIds as $scopeId) {
            $claims = array_merge($claims, $this->claimsByScope[$scopeId] ?? []);
        }

        return array_filter($claims, fn (mixed $value) => $value !== null);
    }
}
