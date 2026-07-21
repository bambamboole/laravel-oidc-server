<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Token;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\PublicKey;
use RuntimeException;
use Throwable;

final class Jwk
{
    /** @return array{kty: string, use: string, alg: string, kid: string, n: string, e: string} */
    public static function fromPem(string $pem): array
    {
        try {
            $key = PublicKeyLoader::load(trim($pem));
        } catch (Throwable $exception) {
            throw new RuntimeException('The given PEM is not a readable public key.', 0, $exception);
        }

        if (! $key instanceof PublicKey) {
            throw new RuntimeException('Only RSA public keys can be converted to a JWK.');
        }

        $decoded = json_decode($key->toString('JWK'), true);
        $jwk = is_array($decoded) ? ($decoded['keys'][0] ?? null) : null;

        if (! is_array($jwk) || ! is_string($jwk['n'] ?? null) || ! is_string($jwk['e'] ?? null)) {
            throw new RuntimeException('Unable to derive JWK parameters from the given RSA public key.');
        }

        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => self::thumbprint($jwk['n'], $jwk['e']),
            'n' => $jwk['n'],
            'e' => $jwk['e'],
        ];
    }

    public static function thumbprint(string $n, string $e): string
    {
        // RFC 7638: members in lexicographic order (e, kty, n), no whitespace.
        $json = json_encode(['e' => $e, 'kty' => 'RSA', 'n' => $n]);

        return self::base64UrlEncode(hash('sha256', $json, true));
    }

    private static function base64UrlEncode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
