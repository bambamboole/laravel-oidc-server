<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Tokens;

use Lcobucci\JWT\Token\Plain;

/**
 * Parses a JWT the realm issued: verifies its signature against the realm's
 * verification keys and that `iss` names the realm's issuer. Returns null
 * for anything that does not parse, was not signed by one of them, or was
 * issued elsewhere; other claims are not validated here.
 */
interface SignedJwtParser
{
    public function parse(string $jwt): ?Plain;
}
