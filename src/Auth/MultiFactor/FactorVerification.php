<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor;

final readonly class FactorVerification
{
    /**
     * @param  list<string>  $amr
     */
    public function __construct(
        public bool $verified,
        public array $amr = [],
    ) {}
}
