<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Testing\InteractsWithOidc;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;

/*
 * peststan only reads uses() declarations from files named Pest.php; this one
 * lets it resolve `$this` as TestCase&InteractsWithOidc in this directory's
 * tests. The tests/Testing ignore entries in phpstan.neon.dist depend on it.
 */
uses(TestCase::class, InteractsWithOidc::class);
