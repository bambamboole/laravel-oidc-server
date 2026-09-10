<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\SignedJwtParser;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Throwable;

/**
 * Parses a JWT the current realm issued: signed by one of the realm's
 * verification keys and carrying the realm's issuer as `iss` (RFC 9068 §4).
 * Every path that accepts an access token — the guard, introspection,
 * revocation, exchange — goes through {@see parse()}, so the issuer check
 * holds for all of them.
 */
class TokenInspector implements SignedJwtParser
{
    public function __construct(
        private readonly SigningKeys $signingKeys,
        private readonly IssuerResolver $issuer,
    ) {}

    public function accessToken(string $jwt): ?AccessToken
    {
        $parsed = $this->parse($jwt);

        return $parsed instanceof Plain ? $this->tokenForParsed($parsed) : null;
    }

    public function parse(string $jwt): ?Plain
    {
        try {
            $parsed = new Parser(new JoseEncoder)->parse($jwt);
        } catch (Throwable) {
            return null;
        }

        if (! $parsed instanceof Plain) {
            return null;
        }

        $validator = new Validator;

        if (! $validator->validate($parsed, new IssuedBy($this->issuer->url()))) {
            return null;
        }

        foreach ($this->signingKeys->verificationKeys() as $key) {
            if ($validator->validate($parsed, new SignedWith(new Sha256, InMemory::plainText($key->publicKeyPem)))) {
                return $parsed;
            }
        }

        return null;
    }

    public function tokenForParsed(Plain $parsed): ?AccessToken
    {
        $jti = $parsed->claims()->get('jti');

        return is_string($jti) ? AccessToken::query()->inRealm()->find($jti) : null;
    }
}
