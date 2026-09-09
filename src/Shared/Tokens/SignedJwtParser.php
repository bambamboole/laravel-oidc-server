<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Tokens;

use Lcobucci\JWT\Token\Plain;

/**
 * Parses a JWT the realm issued and verifies its signature against the
 * realm's verification keys. Returns null for anything that does not parse
 * or was not signed by one of them; claims are not validated here.
 */
interface SignedJwtParser
{
    public function parse(string $jwt): ?Plain;
}
