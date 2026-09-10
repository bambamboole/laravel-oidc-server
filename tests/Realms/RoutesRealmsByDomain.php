<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tests\Realms;

/**
 * Marker for a test file that serves every realm from its own host. The
 * routing mode is fixed when the routes are registered, so TestCase reads it
 * before boot.
 */
trait RoutesRealmsByDomain {}
