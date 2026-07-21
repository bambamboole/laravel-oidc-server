<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Testing;

use Illuminate\Support\Str;

/**
 * An RFC 7636 code verifier and its S256 challenge, for driving the
 * authorization-code flow in tests.
 */
final readonly class PkcePair
{
    public function __construct(
        public string $verifier,
        public string $challenge,
    ) {}

    public static function generate(): self
    {
        $verifier = Str::random(64);

        return new self(
            $verifier,
            rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
        );
    }
}
