<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League;

use League\OAuth2\Server\CryptTrait;
use Throwable;

/**
 * Decrypts the opaque refresh token league hands out, so the revocation and
 * introspection endpoints can read the ids it references.
 */
final class RefreshTokenPayload
{
    use CryptTrait;

    public function __construct(EncryptionKey $key)
    {
        $this->setEncryptionKey($key->value());
    }

    public function decode(string $encrypted): ?object
    {
        try {
            $payload = json_decode($this->decrypt($encrypted));
        } catch (Throwable) {
            return null;
        }

        return is_object($payload) ? $payload : null;
    }
}
