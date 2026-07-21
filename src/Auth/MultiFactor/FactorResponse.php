<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\MultiFactor;

final readonly class FactorResponse
{
    /**
     * @param  array<string, mixed>  $input
     */
    public function __construct(public array $input) {}

    public function string(string $key): string
    {
        $value = $this->input[$key] ?? '';

        return is_string($value) ? $value : '';
    }
}
