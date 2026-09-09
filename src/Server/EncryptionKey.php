<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Server;

use Illuminate\Contracts\Encryption\Encrypter;

/**
 * Encrypts authorization codes and refresh-token payloads. Derived from the
 * application key, so rotating APP_KEY invalidates outstanding codes and
 * refresh tokens — the same trade Passport makes.
 */
final readonly class EncryptionKey
{
    public function __construct(private Encrypter $encrypter) {}

    public function value(): string
    {
        return $this->encrypter->getKey();
    }
}
