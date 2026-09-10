<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\SigningKeys;

use Lcobucci\JWT\Configuration;

/**
 * The realm's current signing key and every key a token may still be verified with.
 */
interface Keyring
{
    public function signingKey(): SigningKeyPair;

    /** @return non-empty-list<SigningKeyPair> */
    public function verificationKeys(): array;

    public function signingKid(): string;

    public function signingConfiguration(): Configuration;
}
