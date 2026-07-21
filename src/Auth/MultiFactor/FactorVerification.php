<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor;

final readonly class FactorVerification
{
    /**
     * @param  list<string>  $amr
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public bool $verified,
        public array $amr = [],
        public array $metadata = [],
    ) {}
}
