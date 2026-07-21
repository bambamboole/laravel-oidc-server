<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Contracts;

use Bambamboole\LaravelOidc\Support\EnvironmentWriteException;

interface EnvironmentStore
{
    /**
     * Atomically upsert the given variables into the environment file.
     *
     * @param  array<string, string>  $variables
     * @param  (callable(string): string)|null  $encoder
     *
     * @throws EnvironmentWriteException
     */
    public function write(array $variables, ?callable $encoder = null): void;

    /**
     * Read the current value of a variable from the environment file, or null
     * when the variable (or the file itself) is absent or empty.
     */
    public function value(string $key): ?string;
}
