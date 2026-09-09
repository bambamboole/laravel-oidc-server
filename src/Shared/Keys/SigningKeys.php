<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Keys;

use Lcobucci\JWT\Configuration;

/**
 * The realm's current signing key and every key a token may still be verified with.
 */
interface SigningKeys
{
    public function signingKey(): SigningKey;

    /** @return non-empty-list<SigningKey> */
    public function verificationKeys(): array;

    public function signingKid(): string;

    public function signingConfiguration(): Configuration;
}
